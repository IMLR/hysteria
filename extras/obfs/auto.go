package obfs

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"

	"github.com/hashicorp/golang-lru/v2/simplelru"
)

const autoMaxPeers = 4096

type autoMode uint8

const (
	autoPlain autoMode = iota
	autoSalamander
	autoGecko
)

const (
	autoPlainFamily uint8 = 1 << iota
	autoObfsFamily
)

// AutoOptions configures server-side plain QUIC, Salamander and Gecko on one
// socket. Both obfuscators use Password; packet sizes only apply to Gecko.
type AutoOptions = GeckoOptions

// autoAddr binds the reply codec to the address retained by QUIC, rather than
// mutable per-peer state. A new handshake cannot change an existing connection's
// reply codec. String and Network preserve the actual client endpoint.
type autoAddr struct {
	net.Addr
	mode autoMode
}

type autoPacket struct {
	data []byte
	addr *autoAddr
}

type autoPacketConn struct {
	*geckoPacketConn
	raw net.PacketConn
	sm  *salamanderObfuscator

	readMu   sync.Mutex
	wireBuf  [udpBufferSize]byte
	plainBuf [udpBufferSize]byte
	pending  *autoPacket

	// Hints avoid trying both wire formats for ordinary data packets. They are
	// bounded, and record a union: a different handshake never revokes a codec.
	// They are not authentication state; QUIC authenticates every candidate.
	peerMu sync.Mutex
	peers  *simplelru.LRU[string, uint8]
}

// WrapPacketConnAuto is for servers only. Clients still explicitly select
// plain QUIC, Salamander or Gecko. Close closes the underlying socket.
func WrapPacketConnAuto(conn net.PacketConn, opts AutoOptions) (net.PacketConn, error) {
	wrapped, err := WrapPacketConnGecko(conn, opts)
	if err != nil {
		return nil, err
	}
	// Gecko already validated the shared password and packet sizes.
	sm, _ := newSalamanderObfuscator(opts.Password)
	peers, _ := simplelru.NewLRU[string, uint8](autoMaxPeers, nil)
	return &autoPacketConn{
		geckoPacketConn: wrapped.(*geckoPacketConn),
		raw:             conn,
		sm:              sm,
		peers:           peers,
	}, nil
}

func (a *autoPacketConn) remember(addr net.Addr, mode autoMode) {
	family := autoObfsFamily
	if mode == autoPlain {
		family = autoPlainFamily
	}
	a.peerMu.Lock()
	defer a.peerMu.Unlock()
	old, _ := a.peers.Get(addr.String())
	a.peers.Add(addr.String(), old|family)
}

func (a *autoPacketConn) families(addr net.Addr) uint8 {
	a.peerMu.Lock()
	defer a.peerMu.Unlock()
	families, _ := a.peers.Get(addr.String())
	return families
}

func (a *autoPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	dst, ok := addr.(*autoAddr)
	if !ok {
		return 0, errors.New("auto obfs: reply requires an address returned by ReadFrom")
	}
	a.remember(dst.Addr, dst.mode)
	switch dst.mode {
	case autoPlain:
		return a.raw.WriteTo(p, dst.Addr)
	case autoSalamander:
		return a.inner.WriteTo(p, dst.Addr)
	case autoGecko:
		return a.geckoPacketConn.WriteTo(p, dst.Addr)
	default:
		return 0, errors.New("auto obfs: invalid reply mode")
	}
}

func (a *autoPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	a.readMu.Lock()
	defer a.readMu.Unlock()
	if a.pending != nil {
		pkt := a.pending
		a.pending = nil
		return copy(p, pkt.data), pkt.addr, nil
	}
	for {
		n, addr, err := a.raw.ReadFrom(a.wireBuf[:])
		if err != nil {
			return 0, addr, err
		}
		if n == 0 {
			continue
		}
		wire := a.wireBuf[:n]
		nn := a.sm.Deobfuscate(wire, a.plainBuf[:])
		decoded := a.plainBuf[:nn]

		// The exact Gecko marker (0x80) is distinct from QUIC's fixed bit.
		// Do not feed an incomplete valid fragment to QUIC as a plain packet.
		if len(decoded) > 0 && decoded[0] == geckoFlagFragment {
			h, chunk, decErr := decodeFrame(decoded)
			if decErr == nil {
				out, ready := a.acceptChunk(addr, h, chunk)
				if ready && autoQUICLong(out) {
					a.remember(addr, autoGecko)
					return copy(p, out), &autoAddr{addr, autoGecko}, nil
				}
				if !autoQUICLong(wire) {
					continue
				}
			}
		}

		plainLong, obfsLong := autoQUICLong(wire), autoQUICLong(decoded)
		if plainLong || obfsLong {
			if plainLong {
				a.remember(addr, autoPlain)
			}
			if obfsLong {
				a.remember(addr, autoSalamander)
				if plainLong {
					a.queue(decoded, addr, autoSalamander)
				} else {
					return copy(p, decoded), &autoAddr{addr, autoSalamander}, nil
				}
			}
			return copy(p, wire), &autoAddr{addr, autoPlain}, nil
		}

		families := a.families(addr)
		plainShort := families != autoObfsFamily && autoQUICShort(wire)
		obfsShort := families != autoPlainFamily && autoQUICShort(decoded)
		// After NAT rebinding, or when one endpoint uses both formats, short
		// headers can be ambiguous. Deliver both candidates for QUIC's AEAD to
		// validate; never guess a connection's reply mode from random salt.
		if plainShort {
			if obfsShort {
				a.queue(decoded, addr, autoSalamander)
			}
			return copy(p, wire), &autoAddr{addr, autoPlain}, nil
		}
		if obfsShort {
			// Gecko and Salamander use identical short-header wire packets.
			return copy(p, decoded), &autoAddr{addr, autoSalamander}, nil
		}
	}
}

func (a *autoPacketConn) queue(p []byte, addr net.Addr, mode autoMode) {
	a.pending = &autoPacket{
		data: append([]byte(nil), p...),
		addr: &autoAddr{addr, mode},
	}
}

// Validate the invariant long header before learning a wire format. In
// particular, Salamander's random salt must not be mistaken for a QUIC header
// just because its first two bits happen to be set. Hysteria uses QUIC v1;
// recognize v2 as well so the transport can return version negotiation.
func autoQUICLong(p []byte) bool {
	if len(p) < 7 || p[0]&0xc0 != 0xc0 {
		return false
	}
	version := binary.BigEndian.Uint32(p[1:5])
	if version != 1 && version != 0x6b3343cf {
		return false
	}
	dcidLen := int(p[5])
	if dcidLen > 20 || len(p) < 7+dcidLen {
		return false
	}
	scidLen := int(p[6+dcidLen])
	return scidLen <= 20 && len(p) > 7+dcidLen+scidLen
}

func autoQUICShort(p []byte) bool {
	return len(p) >= 17 && p[0]&0xc0 == 0x40
}
