package stun

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	DefaultListenAddress = ":3478"
	DefaultPort          = 3478
	DefaultTimeout       = 2 * time.Second

	bindingRequestType = 0x0001
	bindingSuccessType = 0x0101
	magicCookie        = 0x2112A442

	attrXORMappedAddress = 0x0020
)

const (
	NATTypeUnknown      = "UNKNOWN"
	NATTypeOpenInternet = "OPEN_INTERNET"
	NATTypeNAT          = "NAT"
	NATTypeUDPBlocked   = "UDP_BLOCKED"
)

func NewBindingTransactionID() ([12]byte, error) {
	return newTransactionID()
}

type Server struct {
	conn *net.UDPConn
}

type ProbeResult struct {
	ServerAddress string
	LocalAddress  string
	MappedAddress string
	NATType       string
}

func Listen(address string) (*Server, error) {
	bindAddr := strings.TrimSpace(address)
	if bindAddr == "" {
		bindAddr = DefaultListenAddress
	}
	udpAddr, err := net.ResolveUDPAddr("udp", bindAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	server := &Server{conn: conn}
	go server.serve()
	return server, nil
}

func (s *Server) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

func (s *Server) LocalAddr() net.Addr {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

func Probe(serverAddress, localBindAddress string, timeout time.Duration) (ProbeResult, error) {
	result := ProbeResult{
		ServerAddress: strings.TrimSpace(serverAddress),
		NATType:       NATTypeUnknown,
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	serverAddr, err := net.ResolveUDPAddr("udp", result.ServerAddress)
	if err != nil {
		return result, err
	}

	localBindAddress = strings.TrimSpace(localBindAddress)
	if localBindAddress == "" {
		localBindAddress = "0.0.0.0:0"
	}
	localAddr, err := net.ResolveUDPAddr("udp", localBindAddress)
	if err != nil {
		return result, err
	}
	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return result, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return result, err
	}

	transactionID, err := newTransactionID()
	if err != nil {
		return result, err
	}
	request := EncodeBindingRequest(transactionID)
	if _, err := conn.WriteToUDP(request, serverAddr); err != nil {
		result.NATType = NATTypeUDPBlocked
		return result, err
	}

	buffer := make([]byte, 512)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		result.NATType = NATTypeUDPBlocked
		return result, err
	}
	mappedAddr, err := DecodeBindingSuccessResponse(buffer[:n], transactionID)
	if err != nil {
		return result, err
	}

	boundAddr, _ := conn.LocalAddr().(*net.UDPAddr)
	if boundAddr != nil {
		result.LocalAddress = udpAddrString(boundAddr)
	}
	result.MappedAddress = udpAddrString(mappedAddr)
	result.NATType = ClassifyNAT(boundAddr, mappedAddr)
	return result, nil
}

func EncodeBindingRequest(transactionID [12]byte) []byte {
	return encodeBindingRequest(transactionID)
}

func EncodeBindingSuccessResponse(transactionID [12]byte, mappedAddr *net.UDPAddr) ([]byte, error) {
	if mappedAddr == nil {
		return nil, fmt.Errorf("mapped address is required")
	}
	ipv4 := mappedAddr.IP.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("only IPv4 STUN responses are supported")
	}

	attr := make([]byte, 12)
	binary.BigEndian.PutUint16(attr[0:2], attrXORMappedAddress)
	binary.BigEndian.PutUint16(attr[2:4], 8)
	attr[4] = 0
	attr[5] = 0x01
	binary.BigEndian.PutUint16(attr[6:8], uint16(mappedAddr.Port)^uint16(magicCookie>>16))
	cookieBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(cookieBytes, magicCookie)
	for i := 0; i < len(ipv4); i++ {
		attr[8+i] = ipv4[i] ^ cookieBytes[i]
	}

	message := make([]byte, 20+len(attr))
	binary.BigEndian.PutUint16(message[0:2], bindingSuccessType)
	binary.BigEndian.PutUint16(message[2:4], uint16(len(attr)))
	binary.BigEndian.PutUint32(message[4:8], magicCookie)
	copy(message[8:20], transactionID[:])
	copy(message[20:], attr)
	return message, nil
}

func DecodeBindingSuccessResponse(message []byte, transactionID [12]byte) (*net.UDPAddr, error) {
	if len(message) < 20 {
		return nil, errors.New("stun response too short")
	}
	if binary.BigEndian.Uint16(message[0:2]) != bindingSuccessType {
		return nil, errors.New("unexpected stun message type")
	}
	if binary.BigEndian.Uint32(message[4:8]) != magicCookie {
		return nil, errors.New("invalid stun magic cookie")
	}
	if string(message[8:20]) != string(transactionID[:]) {
		return nil, errors.New("stun transaction id mismatch")
	}
	messageLength := int(binary.BigEndian.Uint16(message[2:4]))
	if len(message) < 20+messageLength {
		return nil, errors.New("stun response truncated")
	}

	offset := 20
	for offset+4 <= 20+messageLength {
		attrType := binary.BigEndian.Uint16(message[offset : offset+2])
		attrLength := int(binary.BigEndian.Uint16(message[offset+2 : offset+4]))
		valueStart := offset + 4
		valueEnd := valueStart + attrLength
		if valueEnd > len(message) {
			return nil, errors.New("stun attribute truncated")
		}
		if attrType == attrXORMappedAddress {
			addr, err := decodeXORMappedAddress(message[valueStart:valueEnd])
			if err != nil {
				return nil, err
			}
			return addr, nil
		}
		offset = valueEnd
		if remainder := attrLength % 4; remainder != 0 {
			offset += 4 - remainder
		}
	}
	return nil, errors.New("stun response missing XOR-MAPPED-ADDRESS")
}

func (s *Server) serve() {
	buffer := make([]byte, 512)
	for {
		n, remoteAddr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		transactionID, ok := decodeBindingRequest(buffer[:n])
		if !ok {
			continue
		}
		response, err := EncodeBindingSuccessResponse(transactionID, remoteAddr)
		if err != nil {
			continue
		}
		_, _ = s.conn.WriteToUDP(response, remoteAddr)
	}
}

func decodeBindingRequest(message []byte) ([12]byte, bool) {
	var transactionID [12]byte
	if len(message) < 20 {
		return transactionID, false
	}
	if binary.BigEndian.Uint16(message[0:2]) != bindingRequestType {
		return transactionID, false
	}
	if binary.BigEndian.Uint32(message[4:8]) != magicCookie {
		return transactionID, false
	}
	copy(transactionID[:], message[8:20])
	return transactionID, true
}

func encodeBindingRequest(transactionID [12]byte) []byte {
	message := make([]byte, 20)
	binary.BigEndian.PutUint16(message[0:2], bindingRequestType)
	binary.BigEndian.PutUint32(message[4:8], magicCookie)
	copy(message[8:20], transactionID[:])
	return message
}

func decodeXORMappedAddress(value []byte) (*net.UDPAddr, error) {
	if len(value) < 8 {
		return nil, errors.New("invalid XOR-MAPPED-ADDRESS attribute")
	}
	family := value[1]
	if family != 0x01 {
		return nil, errors.New("only IPv4 XOR-MAPPED-ADDRESS is supported")
	}
	port := binary.BigEndian.Uint16(value[2:4]) ^ uint16(magicCookie>>16)
	cookieBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(cookieBytes, magicCookie)
	ip := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		ip[i] = value[4+i] ^ cookieBytes[i]
	}
	return &net.UDPAddr{IP: ip, Port: int(port)}, nil
}

func newTransactionID() ([12]byte, error) {
	var transactionID [12]byte
	_, err := rand.Read(transactionID[:])
	return transactionID, err
}

func ClassifyNAT(localAddr, mappedAddr *net.UDPAddr) string {
	if localAddr == nil || mappedAddr == nil {
		return NATTypeUnknown
	}
	if localAddr.Port == mappedAddr.Port && localAddr.IP != nil && mappedAddr.IP != nil && localAddr.IP.Equal(mappedAddr.IP) {
		return NATTypeOpenInternet
	}
	return NATTypeNAT
}

func udpAddrString(addr *net.UDPAddr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}
