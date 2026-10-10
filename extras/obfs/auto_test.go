package obfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func autoLongPacket() []byte {
	p := quicLong(1200)
	binary.BigEndian.PutUint32(p[1:5], 1)
	p[5] = 8
	p[14] = 8
	return p
}

func wrapAutoTestClient(t *testing.T, conn net.PacketConn, mode autoMode) net.PacketConn {
	t.Helper()
	switch mode {
	case autoPlain:
		return conn
	case autoSalamander:
		wrapped, err := WrapPacketConnSalamander(conn, []byte("shared-password"))
		require.NoError(t, err)
		return wrapped
	default:
		return mustWrapGecko(t, conn, "shared-password")
	}
}

func TestAutoModesShareSocket(t *testing.T) {
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	server, err := WrapPacketConnAuto(raw, AutoOptions{Password: []byte("shared-password")})
	require.NoError(t, err)
	defer server.Close()
	require.NoError(t, server.SetDeadline(time.Now().Add(5*time.Second)))
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		for range 6 {
			n, addr, err := server.ReadFrom(buf)
			if err == nil {
				_, err = server.WriteTo(buf[:n], addr)
			}
			if err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	var wg sync.WaitGroup
	for _, mode := range []autoMode{autoPlain, autoSalamander, autoGecko} {
		wg.Go(func() {
			clientRaw, err := net.ListenPacket("udp", "127.0.0.1:0")
			require.NoError(t, err)
			client := wrapAutoTestClient(t, clientRaw, mode)
			defer client.Close()
			require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
			for _, payload := range [][]byte{autoLongPacket(), quicShort(900)} {
				_, err := client.WriteTo(payload, server.LocalAddr())
				require.NoError(t, err)
				buf := make([]byte, 2048)
				n, _, err := client.ReadFrom(buf)
				require.NoError(t, err)
				require.Equal(t, payload, buf[:n], "mode %d", mode)
			}
		})
	}
	wg.Wait()
	require.NoError(t, <-done)
	require.Implements(t, (*udpLikePacketConn)(nil), server)
	_, err = server.(udpLikePacketConn).SyscallConn()
	require.NoError(t, err)
}

func TestAutoModeSwitchKeepsReplyCodec(t *testing.T) {
	clientAddr, serverAddr := makeAddrs()
	clientRaw, serverRaw := newMemPipe(clientAddr, serverAddr)
	server, err := WrapPacketConnAuto(serverRaw, AutoOptions{Password: []byte("shared-password")})
	require.NoError(t, err)
	defer server.Close()
	defer clientRaw.Close()
	var addresses []net.Addr
	var clients []net.PacketConn
	payload := autoLongPacket()
	buf := make([]byte, 2048)
	for _, mode := range []autoMode{autoPlain, autoSalamander, autoGecko} {
		client := wrapAutoTestClient(t, clientRaw, mode)
		defer client.Close()
		clients = append(clients, client)
		_, err := client.WriteTo(payload, serverAddr)
		require.NoError(t, err)
		var addr net.Addr
		for attempts := 0; ; attempts++ {
			n, candidate, err := server.ReadFrom(buf)
			require.NoError(t, err)
			if candidate.(*autoAddr).mode == mode {
				require.Equal(t, payload, buf[:n])
				addr = candidate
				break
			}
			// Once this endpoint has used plain QUIC, Gecko's random salt
			// may also yield short-header candidates for QUIC to reject.
			require.Equal(t, autoGecko, mode)
			require.Equal(t, autoPlain, candidate.(*autoAddr).mode)
			require.True(t, autoQUICShort(buf[:n]))
			require.Less(t, attempts, geckoMaxFragmentChunks)
		}
		require.Equal(t, clientAddr.String(), addr.String())
		require.Equal(t, clientAddr.Network(), addr.Network())
		addresses = append(addresses, addr)
	}
	// Reply using saved addresses after the same endpoint has selected all
	// three modes. No later handshake may downgrade an earlier reply.
	for i, addr := range addresses {
		_, err := server.WriteTo(payload, addr)
		require.NoError(t, err)
		n, _, err := clients[i].ReadFrom(buf)
		require.NoError(t, err)
		require.Equal(t, payload, buf[:n])
	}
	_, err = server.WriteTo(payload, clientAddr)
	require.Error(t, err)
}

func TestAutoUnknownPeerAmbiguousShortHeader(t *testing.T) {
	clientAddr, serverAddr := makeAddrs()
	clientRaw, serverRaw := newMemPipe(clientAddr, serverAddr)
	server, err := WrapPacketConnAuto(serverRaw, AutoOptions{Password: []byte("shared-password")})
	require.NoError(t, err)
	defer server.Close()
	defer clientRaw.Close()
	sm, err := newSalamanderObfuscator([]byte("shared-password"))
	require.NoError(t, err)
	payload := quicShort(300)
	wire := make([]byte, len(payload)+smSaltLen)
	for {
		sm.Obfuscate(payload, wire)
		if autoQUICShort(wire) {
			break
		}
	}
	_, err = clientRaw.WriteTo(wire, serverAddr)
	require.NoError(t, err)
	buf := make([]byte, 2048)
	n, first, err := server.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, wire, buf[:n])
	require.Equal(t, autoPlain, first.(*autoAddr).mode)
	n, second, err := server.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, payload, buf[:n])
	require.Equal(t, autoSalamander, second.(*autoAddr).mode)
	_, err = server.WriteTo(payload, second)
	require.NoError(t, err)
	client := wrapAutoTestClient(t, clientRaw, autoSalamander)
	n, _, err = client.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, payload, buf[:n])
}

func TestAutoHintsBounded(t *testing.T) {
	clientAddr, serverAddr := makeAddrs()
	c, s := newMemPipe(clientAddr, serverAddr)
	defer c.Close()
	wrapped, err := WrapPacketConnAuto(s, AutoOptions{Password: []byte("shared-password")})
	require.NoError(t, err)
	defer wrapped.Close()
	a := wrapped.(*autoPacketConn)
	for i := range autoMaxPeers * 2 {
		a.remember(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: i}, autoPlain)
	}
	require.Equal(t, autoMaxPeers, a.peers.Len())
	a.remember(clientAddr, autoPlain)
	a.remember(clientAddr, autoGecko)
	require.Equal(t, autoPlainFamily|autoObfsFamily, a.families(clientAddr))
}

func TestAutoReusedNATEndpoint(t *testing.T) {
	clientAddr, serverAddr := makeAddrs()
	c, s := newMemPipe(clientAddr, serverAddr)
	defer c.Close()
	wrapped, err := WrapPacketConnAuto(s, AutoOptions{Password: []byte("shared-password")})
	require.NoError(t, err)
	defer wrapped.Close()
	a := wrapped.(*autoPacketConn)
	a.remember(clientAddr, autoPlain)
	sm, err := newSalamanderObfuscator([]byte("shared-password"))
	require.NoError(t, err)
	payload := quicShort(300)
	wire := make([]byte, len(payload)+smSaltLen)
	for {
		sm.Obfuscate(payload, wire)
		if !autoQUICShort(wire) && !autoQUICLong(wire) {
			break
		}
	}
	_, err = c.WriteTo(wire, serverAddr)
	require.NoError(t, err)
	buf := make([]byte, 2048)
	n, addr, err := a.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, payload, buf[:n])
	require.Equal(t, autoSalamander, addr.(*autoAddr).mode)
	require.Equal(t, autoPlainFamily|autoObfsFamily, a.families(clientAddr))
}

func TestAutoPlainDataResemblingGeckoFragment(t *testing.T) {
	clientAddr, serverAddr := makeAddrs()
	c, s := newMemPipe(clientAddr, serverAddr)
	defer c.Close()
	wrapped, err := WrapPacketConnAuto(s, AutoOptions{Password: []byte("shared-password")})
	require.NoError(t, err)
	defer wrapped.Close()
	a := wrapped.(*autoPacketConn)
	a.remember(clientAddr, autoPlain)
	frame := make([]byte, geckoHeaderSize+100)
	_, err = encodeFrame(frameHeader{totalChunks: 2}, make([]byte, 100), frame)
	require.NoError(t, err)
	sm, err := newSalamanderObfuscator([]byte("shared-password"))
	require.NoError(t, err)
	wire := make([]byte, len(frame)+smSaltLen)
	for {
		sm.Obfuscate(frame, wire)
		if autoQUICShort(wire) {
			break
		}
	}
	_, err = c.WriteTo(wire, serverAddr)
	require.NoError(t, err)
	buf := make([]byte, 2048)
	n, addr, err := a.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, wire, buf[:n])
	require.Equal(t, autoPlain, addr.(*autoAddr).mode)
}

func TestAutoValidatesOptionsAndLongHeaders(t *testing.T) {
	for _, opts := range []AutoOptions{
		{}, {Password: []byte("abc")},
		{Password: []byte("password"), MinPacketSize: 1200, MaxPacketSize: 512},
	} {
		_, err := WrapPacketConnAuto(nil, opts)
		require.Error(t, err)
	}
	valid := autoLongPacket()
	require.True(t, autoQUICLong(valid))
	for n := range 23 {
		require.False(t, autoQUICLong(valid[:n]), fmt.Sprint(n))
	}
	for _, offset := range []int{0, 1, 5, 14} {
		invalid := bytes.Clone(valid)
		invalid[offset] = 0xff
		if offset == 0 {
			invalid[offset] = geckoFlagFragment
		}
		require.False(t, autoQUICLong(invalid))
	}
}
