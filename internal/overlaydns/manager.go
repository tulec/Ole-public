package overlaydns

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
)

const (
	typeA    = 1
	typeAAAA = 28
	classIN  = 1
)

type Status struct {
	ListenAddress string `json:"listenAddress"`
	Domain        string `json:"domain"`
	RecordCount   int    `json:"recordCount"`
	LastError     string `json:"lastError"`
}

type Manager interface {
	Address() string
	Domain() string
	Reconcile(records map[string]string) error
	Snapshot() Status
	Close() error
}

type manager struct {
	mu      sync.RWMutex
	conn    *net.UDPConn
	records map[string]string
	status  Status
}

type noopManager struct {
	status Status
}

func New(listenAddress, domain string) Manager {
	listenAddress = strings.TrimSpace(listenAddress)
	domain = normalizeDomain(domain)
	if listenAddress == "" || domain == "" {
		return &noopManager{status: Status{ListenAddress: listenAddress, Domain: domain}}
	}
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddress)
	if err != nil {
		return &noopManager{status: Status{ListenAddress: listenAddress, Domain: domain, LastError: err.Error()}}
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return &noopManager{status: Status{ListenAddress: listenAddress, Domain: domain, LastError: err.Error()}}
	}
	m := &manager{
		conn:    conn,
		records: map[string]string{},
		status: Status{
			ListenAddress: conn.LocalAddr().String(),
			Domain:        domain,
		},
	}
	go m.serve()
	return m
}

func (m *manager) Address() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status.ListenAddress
}

func (m *manager) Domain() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status.Domain
}

func (m *manager) Reconcile(records map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next := make(map[string]string, len(records))
	for name, ip := range records {
		normalizedName := normalizeName(name)
		parsedIP := net.ParseIP(strings.TrimSpace(ip)).To4()
		if normalizedName == "" || parsedIP == nil {
			continue
		}
		next[normalizedName] = parsedIP.String()
	}
	m.records = next
	m.status.RecordCount = len(next)
	m.status.LastError = ""
	return nil
}

func (m *manager) Snapshot() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

func (m *manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.conn == nil {
		return nil
	}
	err := m.conn.Close()
	m.conn = nil
	return err
}

func (m *manager) serve() {
	buffer := make([]byte, 1500)
	for {
		n, addr, err := m.conn.ReadFromUDP(buffer)
		if err != nil {
			m.mu.Lock()
			if m.status.LastError == "" {
				m.status.LastError = err.Error()
			}
			m.mu.Unlock()
			return
		}
		response := m.handleQuery(buffer[:n])
		if len(response) == 0 {
			continue
		}
		_, _ = m.conn.WriteToUDP(response, addr)
	}
}

func (m *manager) handleQuery(packet []byte) []byte {
	m.mu.RLock()
	records := make(map[string]string, len(m.records))
	for name, ip := range m.records {
		records[name] = ip
	}
	m.mu.RUnlock()
	response, err := buildResponse(packet, records)
	if err != nil {
		m.mu.Lock()
		m.status.LastError = err.Error()
		m.mu.Unlock()
		return nil
	}
	return response
}

func (m *noopManager) Address() string {
	return m.status.ListenAddress
}

func (m *noopManager) Domain() string {
	return m.status.Domain
}

func (m *noopManager) Reconcile(_ map[string]string) error {
	return nil
}

func (m *noopManager) Snapshot() Status {
	return m.status
}

func (m *noopManager) Close() error {
	return nil
}

func normalizeDomain(domain string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
}

func normalizeName(name string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(name)), ".")
}

func buildResponse(packet []byte, records map[string]string) ([]byte, error) {
	if len(packet) < 12 {
		return nil, fmt.Errorf("dns query too short")
	}
	id := binary.BigEndian.Uint16(packet[0:2])
	flags := binary.BigEndian.Uint16(packet[2:4])
	questionCount := int(binary.BigEndian.Uint16(packet[4:6]))
	if questionCount < 1 {
		return nil, fmt.Errorf("dns query without question")
	}
	offset := 12
	name, nameEnd, err := parseQName(packet, offset)
	if err != nil {
		return nil, err
	}
	offset = nameEnd
	if len(packet) < offset+4 {
		return nil, fmt.Errorf("dns query missing type/class")
	}
	qtype := binary.BigEndian.Uint16(packet[offset : offset+2])
	qclass := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
	offset += 4
	if qclass != classIN {
		return buildHeaderOnlyResponse(id, flags, packet[12:offset], 4), nil
	}
	answerIP := records[normalizeName(name)]
	answerCount := uint16(0)
	rcode := uint16(0)
	if answerIP == "" {
		rcode = 3
	} else if qtype == typeA || qtype == typeAAAA || qtype == 255 {
		if qtype == typeA || qtype == 255 {
			answerCount = 1
			rcode = 0
		}
	}
	response := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(response[0:2], id)
	responseFlags := uint16(0x8000 | 0x0400 | (flags & 0x0100) | rcode)
	binary.BigEndian.PutUint16(response[2:4], responseFlags)
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], answerCount)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], 0)
	response = append(response, packet[12:offset]...)
	if answerCount == 0 {
		return response, nil
	}
	parsedIP := net.ParseIP(answerIP).To4()
	if parsedIP == nil {
		return buildHeaderOnlyResponse(id, flags, packet[12:offset], 3), nil
	}
	response = append(response, 0xC0, 0x0C)
	answer := make([]byte, 10)
	binary.BigEndian.PutUint16(answer[0:2], typeA)
	binary.BigEndian.PutUint16(answer[2:4], classIN)
	binary.BigEndian.PutUint32(answer[4:8], 30)
	binary.BigEndian.PutUint16(answer[8:10], 4)
	response = append(response, answer...)
	response = append(response, parsedIP...)
	return response, nil
}

func buildHeaderOnlyResponse(id, flags uint16, question []byte, rcode uint16) []byte {
	response := make([]byte, 12, 12+len(question))
	binary.BigEndian.PutUint16(response[0:2], id)
	binary.BigEndian.PutUint16(response[2:4], 0x8000|0x0400|(flags&0x0100)|rcode)
	binary.BigEndian.PutUint16(response[4:6], 1)
	response = append(response, question...)
	return response
}

func parseQName(packet []byte, offset int) (string, int, error) {
	labels := make([]string, 0, 4)
	for {
		if offset >= len(packet) {
			return "", 0, fmt.Errorf("dns qname overflow")
		}
		length := int(packet[offset])
		offset++
		if length == 0 {
			return strings.Join(labels, "."), offset, nil
		}
		if length&0xC0 != 0 {
			return "", 0, fmt.Errorf("dns compression is not supported in queries")
		}
		if offset+length > len(packet) {
			return "", 0, fmt.Errorf("dns label overflow")
		}
		labels = append(labels, string(packet[offset:offset+length]))
		offset += length
	}
}

func LookupHost(ctx context.Context, serverAddress, host string) ([]string, error) {
	serverAddress = strings.TrimSpace(serverAddress)
	host = normalizeName(host)
	if serverAddress == "" || host == "" {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	query, queryID, err := buildLookupQuery(host)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", serverAddress)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}
	return parseLookupResponse(buffer[:n], queryID, host)
}

func buildLookupQuery(host string) ([]byte, uint16, error) {
	labels := strings.Split(normalizeName(host), ".")
	if len(labels) == 0 {
		return nil, 0, fmt.Errorf("dns query host is empty")
	}
	queryID := uint16(1)
	packet := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(packet[0:2], queryID)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return nil, 0, fmt.Errorf("invalid dns label %q", label)
		}
		packet = append(packet, byte(len(label)))
		packet = append(packet, []byte(label)...)
	}
	packet = append(packet, 0)
	question := make([]byte, 4)
	binary.BigEndian.PutUint16(question[0:2], typeA)
	binary.BigEndian.PutUint16(question[2:4], classIN)
	packet = append(packet, question...)
	return packet, queryID, nil
}

func parseLookupResponse(packet []byte, expectedID uint16, host string) ([]string, error) {
	if len(packet) < 12 {
		return nil, fmt.Errorf("dns response too short")
	}
	if binary.BigEndian.Uint16(packet[0:2]) != expectedID {
		return nil, fmt.Errorf("dns response id mismatch")
	}
	flags := binary.BigEndian.Uint16(packet[2:4])
	rcode := flags & 0x000F
	questionCount := int(binary.BigEndian.Uint16(packet[4:6]))
	answerCount := int(binary.BigEndian.Uint16(packet[6:8]))
	offset := 12
	for idx := 0; idx < questionCount; idx++ {
		_, nextOffset, err := parseQName(packet, offset)
		if err != nil {
			return nil, err
		}
		offset = nextOffset
		if len(packet) < offset+4 {
			return nil, fmt.Errorf("dns response missing question type/class")
		}
		offset += 4
	}
	if rcode == 3 || answerCount == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	hosts := make([]string, 0, answerCount)
	for idx := 0; idx < answerCount; idx++ {
		nextOffset, err := skipDNSName(packet, offset)
		if err != nil {
			return nil, err
		}
		offset = nextOffset
		if len(packet) < offset+10 {
			return nil, fmt.Errorf("dns response missing answer header")
		}
		answerType := binary.BigEndian.Uint16(packet[offset : offset+2])
		answerClass := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
		rdLength := int(binary.BigEndian.Uint16(packet[offset+8 : offset+10]))
		offset += 10
		if len(packet) < offset+rdLength {
			return nil, fmt.Errorf("dns response missing answer payload")
		}
		if answerType == typeA && answerClass == classIN && rdLength == 4 {
			hosts = append(hosts, net.IP(packet[offset:offset+rdLength]).String())
		}
		offset += rdLength
	}
	if len(hosts) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return hosts, nil
}

func skipDNSName(packet []byte, offset int) (int, error) {
	for {
		if offset >= len(packet) {
			return 0, fmt.Errorf("dns name overflow")
		}
		length := int(packet[offset])
		if length == 0 {
			return offset + 1, nil
		}
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(packet) {
				return 0, fmt.Errorf("dns compressed name overflow")
			}
			return offset + 2, nil
		}
		offset++
		if offset+length > len(packet) {
			return 0, fmt.Errorf("dns label overflow")
		}
		offset += length
	}
}
