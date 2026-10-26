//go:build !darwin && !linux

package rootnet

import "net"

func readDatagram(c net.Conn, b []byte) (int, error) { return c.Read(b) }

func waitUDPReadable(net.Conn) error { return nil }
