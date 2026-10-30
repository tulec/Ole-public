package transportauth

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

const RelayMagic = "OLER2"

var ErrDatagramTooLarge = errors.New("UDP datagram exceeds the 1200-byte wire budget")
var ErrMalformedDatagram = errors.New("malformed UDP datagram")

type wireWriter struct {
	b   []byte
	err error
}

func (w *wireWriter) byte(v int) {
	if v < 0 || v > 255 {
		w.err = ErrMalformedDatagram
		return
	}
	w.b = append(w.b, byte(v))
}
func (w *wireWriter) number(v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	w.b = append(w.b, b[:]...)
}
func (w *wireWriter) short(v int) {
	if v < 0 || v > 65535 {
		w.err = ErrMalformedDatagram
		return
	}
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(v))
	w.b = append(w.b, b[:]...)
}
func (w *wireWriter) text(s string, max int, empty bool) {
	if len(s) > max || (!empty && s == "") {
		w.err = ErrMalformedDatagram
		return
	}
	w.byte(len(s))
	w.b = append(w.b, s...)
}
func (w *wireWriter) peer(s string) {
	if !atom(s) || len(s) > MaxPeerIDBytes {
		w.err = ErrMalformedDatagram
		return
	}
	w.text(s, MaxPeerIDBytes, false)
}
func (w *wireWriter) hex(s string, n int) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != n {
		w.err = ErrMalformedDatagram
		return
	}
	w.b = append(w.b, b...)
}
func (w *wireWriter) base64(s string, n int) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != n {
		w.err = ErrMalformedDatagram
		return
	}
	w.b = append(w.b, b...)
}
func (w *wireWriter) finish() ([]byte, error) {
	if w.err != nil {
		return nil, w.err
	}
	if len(w.b) > DatagramBudget {
		return nil, ErrDatagramTooLarge
	}
	return w.b, nil
}

type wireReader struct {
	b   []byte
	at  int
	err error
}

func (r *wireReader) take(n int) []byte {
	if n < 0 || n > len(r.b)-r.at {
		r.err = ErrMalformedDatagram
		return nil
	}
	b := r.b[r.at : r.at+n]
	r.at += n
	return b
}
func (r *wireReader) byte() int {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return int(b[0])
}
func (r *wireReader) number() uint64 {
	b := r.take(8)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
func (r *wireReader) short() int {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return int(binary.BigEndian.Uint16(b))
}
func (r *wireReader) text(max int, empty bool) string {
	n := r.byte()
	s := string(r.take(n))
	if n > max || (!empty && n == 0) {
		r.err = ErrMalformedDatagram
	}
	return s
}
func (r *wireReader) peer() string {
	s := r.text(MaxPeerIDBytes, false)
	if !atom(s) {
		r.err = ErrMalformedDatagram
	}
	return s
}
func (r *wireReader) rest() []byte { return r.take(len(r.b) - r.at) }
func (r *wireReader) done() error {
	if r.err != nil || r.at != len(r.b) {
		return ErrMalformedDatagram
	}
	return nil
}
func wireNumber(s string) (uint64, error) { return strconv.ParseUint(s, 10, 64) }
func wireInt(s string) int {
	v, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return v
}
func kindCode(kind string) int {
	switch kind {
	case "packet":
		return 1
	case "data":
		return 2
	case "dataack":
		return 3
	case "probe":
		return 4
	case "ack":
		return 5
	case "hello":
		return 6
	case "welcome":
		return 7
	case "finish":
		return 8
	case "ready":
		return 9
	case "fragment":
		return 10
	}
	return 0
}
func codeKind(code int) string {
	for _, kind := range []string{"packet", "data", "dataack", "probe", "ack", "hello", "welcome", "finish", "ready", "fragment"} {
		if kindCode(kind) == code {
			return kind
		}
	}
	return ""
}

func EncodeTransport(message string) ([]byte, error) {
	p := strings.Split(message, "|")
	if len(p) < 4 || p[0] != Magic {
		return nil, ErrMalformedDatagram
	}
	p = p[1:]
	kind := p[0]
	code := kindCode(kind)
	if code == 0 {
		return nil, ErrMalformedDatagram
	}
	w := wireWriter{b: []byte("OLP4")}
	w.byte(code)
	w.peer(p[1])
	w.peer(p[2])
	switch kind {
	case "probe", "ack":
		if len(p) != 4 {
			return nil, ErrMalformedDatagram
		}
		w.text(p[3], 64, false)
	case "hello", "welcome", "finish", "ready":
		if len(p) != 5 {
			return nil, ErrMalformedDatagram
		}
		raw, err := base64.StdEncoding.DecodeString(p[4])
		if err != nil {
			return nil, ErrMalformedDatagram
		}
		var t transcript
		if json.Unmarshal(raw, &t) != nil || t.ID != p[3] {
			return nil, ErrMalformedDatagram
		}
		initiator := kind == "hello" || kind == "finish"
		i, r := p[1], p[2]
		if !initiator {
			i, r = r, i
		}
		if t.Initiator != i || t.Responder != r {
			return nil, ErrMalformedDatagram
		}
		w.hex(t.ID, 16)
		w.text(t.Network, 128, false)
		w.text(t.InitiatorDevice, 128, false)
		w.text(t.ResponderDevice, 128, false)
		w.base64(t.InitiatorKey, 32)
		if kind != "hello" {
			w.base64(t.ResponderKey, 32)
		} else if t.ResponderKey != "" {
			return nil, ErrMalformedDatagram
		}
		w.base64(t.Signature, 64)
	case "packet", "data", "dataack":
		expected := 6
		if kind == "dataack" {
			expected = 7
		}
		if len(p) != expected {
			return nil, ErrMalformedDatagram
		}
		counterAt := 4
		var reference uint64
		var err error
		if kind == "dataack" {
			reference, err = wireNumber(p[4])
			counterAt = 5
		}
		counter, e := wireNumber(p[counterAt])
		if err != nil || e != nil || counter == 0 || !recordKind(kind, reference) {
			return nil, ErrMalformedDatagram
		}
		w.hex(p[3], 16)
		w.number(counter)
		w.number(reference)
		body, err := hex.DecodeString(p[len(p)-1])
		if err != nil || len(body) < 16 || len(body) > MaxCipherBytes {
			return nil, ErrMalformedDatagram
		}
		w.b = append(w.b, body...)
	case "fragment":
		if len(p) != 12 {
			return nil, ErrMalformedDatagram
		}
		counter, err := wireNumber(p[5])
		reference, e := wireNumber(p[6])
		data, e2 := hex.DecodeString(p[11])
		tag, e3 := hex.DecodeString(p[10])
		if err != nil || e != nil || e2 != nil || e3 != nil {
			return nil, ErrMalformedDatagram
		}
		f := Fragment{Kind: p[4], Counter: counter, Reference: reference, Index: wireInt(p[7]), Count: wireInt(p[8]), Total: wireInt(p[9]), Data: data, Tag: tag}
		if !validFragment(f) {
			return nil, ErrMalformedDatagram
		}
		w.hex(p[3], 16)
		w.byte(kindCode(f.Kind))
		w.number(counter)
		w.number(reference)
		w.byte(f.Index)
		w.byte(f.Count)
		w.short(f.Total)
		w.b = append(w.b, tag...)
		w.b = append(w.b, data...)
	}
	return w.finish()
}

func DecodeTransport(data []byte) ([]string, error) {
	if len(data) > DatagramBudget {
		return nil, ErrDatagramTooLarge
	}
	r := wireReader{b: data}
	if !bytes.Equal(r.take(4), []byte("OLP4")) {
		return nil, ErrMalformedDatagram
	}
	kind := codeKind(r.byte())
	if kind == "" {
		return nil, ErrMalformedDatagram
	}
	source, target := r.peer(), r.peer()
	p := []string{kind, source, target}
	switch kind {
	case "probe", "ack":
		p = append(p, r.text(64, false))
	case "hello", "welcome", "finish", "ready":
		t := transcript{ID: hex.EncodeToString(r.take(16)), Network: r.text(128, false), InitiatorDevice: r.text(128, false), ResponderDevice: r.text(128, false), InitiatorKey: base64.StdEncoding.EncodeToString(r.take(32))}
		t.Initiator, t.Responder = source, target
		if kind == "welcome" || kind == "ready" {
			t.Initiator, t.Responder = target, source
		}
		if kind != "hello" {
			t.ResponderKey = base64.StdEncoding.EncodeToString(r.take(32))
		}
		t.Signature = base64.StdEncoding.EncodeToString(r.take(64))
		raw, _ := json.Marshal(t)
		p = append(p, t.ID, base64.StdEncoding.EncodeToString(raw))
	case "packet", "data", "dataack":
		id := hex.EncodeToString(r.take(16))
		counter, reference := r.number(), r.number()
		body := r.rest()
		if counter == 0 || !recordKind(kind, reference) || len(body) < 16 || len(body) > MaxCipherBytes {
			return nil, ErrMalformedDatagram
		}
		p = append(p, id)
		if kind == "dataack" {
			p = append(p, strconv.FormatUint(reference, 10))
		}
		p = append(p, strconv.FormatUint(counter, 10), hex.EncodeToString(body))
	case "fragment":
		id := hex.EncodeToString(r.take(16))
		f := Fragment{Kind: codeKind(r.byte()), Counter: r.number(), Reference: r.number(), Index: r.byte(), Count: r.byte(), Total: r.short(), Tag: r.take(16), Data: r.rest()}
		if !validFragment(f) {
			return nil, ErrMalformedDatagram
		}
		p = append(p, id, f.Kind, strconv.FormatUint(f.Counter, 10), strconv.FormatUint(f.Reference, 10), strconv.Itoa(f.Index), strconv.Itoa(f.Count), strconv.Itoa(f.Total), hex.EncodeToString(f.Tag), hex.EncodeToString(f.Data))
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return p, nil
}

func TransportText(parts []string) string {
	return strings.Join(append([]string{Magic}, parts...), "|")
}
func RelayText(parts []string) string {
	return strings.Join(append([]string{RelayMagic}, parts...), "|")
}

func encodeRelayPayload(w *wireWriter, payload []byte, source, target string) {
	if strings.HasPrefix(string(payload), Magic+"|") {
		parts := strings.Split(string(payload), "|")
		if len(parts) < 4 || parts[2] != source || (target != "" && parts[3] != target) {
			w.err = ErrMalformedDatagram
			return
		}
		data, err := EncodeTransport(string(payload))
		if err != nil {
			w.err = err
			return
		}
		w.byte(1)
		w.b = append(w.b, data...)
	} else {
		w.byte(0)
		w.peer(source)
		if target != "" {
			w.peer(target)
		}
		w.b = append(w.b, payload...)
	}
}
func decodeRelayPayload(r *wireReader, send bool) (string, string, []byte) {
	mode := r.byte()
	if mode == 1 {
		parts, err := DecodeTransport(r.rest())
		if err != nil {
			r.err = err
			return "", "", nil
		}
		return parts[1], parts[2], []byte(TransportText(parts))
	}
	if mode != 0 {
		r.err = ErrMalformedDatagram
		return "", "", nil
	}
	source := r.peer()
	target := ""
	if send {
		target = r.peer()
	}
	return source, target, r.rest()
}

func EncodeRelay(message string) ([]byte, error) {
	p := strings.Split(message, "|")
	if len(p) < 2 || p[0] != RelayMagic {
		return nil, ErrMalformedDatagram
	}
	p = p[1:]
	w := wireWriter{b: []byte("OLR2")}
	switch p[0] {
	case "bind":
		if len(p) != 4 {
			return nil, ErrMalformedDatagram
		}
		w.byte(1)
		if len(p[1]) > MaxTokenBytes || strings.Contains(p[1], "|") {
			return nil, ErrMalformedDatagram
		}
		w.short(len(p[1]))
		w.b = append(w.b, p[1]...)
		w.peer(p[2])
		w.text(p[3], 64, false)
	case "bound":
		if len(p) != 3 {
			return nil, ErrMalformedDatagram
		}
		w.byte(2)
		w.peer(p[1])
		w.text(p[2], 64, false)
	case "send":
		if len(p) != 5 {
			return nil, ErrMalformedDatagram
		}
		w.byte(3)
		if len(p[1]) > MaxTokenBytes {
			return nil, ErrMalformedDatagram
		}
		w.short(len(p[1]))
		w.b = append(w.b, p[1]...)
		payload, err := hex.DecodeString(p[4])
		if err != nil {
			return nil, ErrMalformedDatagram
		}
		encodeRelayPayload(&w, payload, p[2], p[3])
	case "deliver":
		if len(p) != 3 {
			return nil, ErrMalformedDatagram
		}
		w.byte(4)
		payload, err := hex.DecodeString(p[2])
		if err != nil {
			return nil, ErrMalformedDatagram
		}
		encodeRelayPayload(&w, payload, p[1], "")
	case "error":
		p = strings.SplitN(message, "|", 5)[1:]
		if len(p) != 4 {
			return nil, ErrMalformedDatagram
		}
		w.byte(5)
		w.text(p[1], 64, false)
		w.text(p[2], MaxPeerIDBytes, true)
		w.text(p[3], 255, true)
	default:
		return nil, ErrMalformedDatagram
	}
	return w.finish()
}

func DecodeRelay(data []byte) ([]string, error) {
	if len(data) > DatagramBudget {
		return nil, ErrDatagramTooLarge
	}
	r := wireReader{b: data}
	if !bytes.Equal(r.take(4), []byte("OLR2")) {
		return nil, ErrMalformedDatagram
	}
	var p []string
	switch r.byte() {
	case 1, 3:
		kind := "bind"
		if data[4] == 3 {
			kind = "send"
		}
		size := r.short()
		if size > MaxTokenBytes {
			return nil, ErrMalformedDatagram
		}
		token := string(r.take(size))
		if strings.Contains(token, "|") {
			return nil, ErrMalformedDatagram
		}
		if kind == "bind" {
			p = []string{kind, token, r.peer(), r.text(64, false)}
		} else {
			source, target, payload := decodeRelayPayload(&r, true)
			p = []string{kind, token, source, target, hex.EncodeToString(payload)}
		}
	case 2:
		p = []string{"bound", r.peer(), r.text(64, false)}
	case 4:
		source, _, payload := decodeRelayPayload(&r, false)
		p = []string{"deliver", source, hex.EncodeToString(payload)}
	case 5:
		p = []string{"error", r.text(64, false), r.text(MaxPeerIDBytes, true), r.text(255, true)}
	default:
		return nil, ErrMalformedDatagram
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return p, nil
}

func RelayPayloadBytes(payload []byte) (int, error) {
	if strings.HasPrefix(string(payload), Magic+"|") {
		b, err := EncodeTransport(string(payload))
		return len(b), err
	}
	return len(payload), nil
}

func FragmentText(source, target, session string, f Fragment) string {
	return TransportText([]string{"fragment", source, target, session, f.Kind, strconv.FormatUint(f.Counter, 10), strconv.FormatUint(f.Reference, 10), strconv.Itoa(f.Index), strconv.Itoa(f.Count), strconv.Itoa(f.Total), hex.EncodeToString(f.Tag), hex.EncodeToString(f.Data)})
}
func ParseFragment(p []string) (Fragment, error) {
	if len(p) != 12 {
		return Fragment{}, ErrMalformedDatagram
	}
	c, e := wireNumber(p[5])
	ref, e2 := wireNumber(p[6])
	tag, e3 := hex.DecodeString(p[10])
	data, e4 := hex.DecodeString(p[11])
	if e != nil || e2 != nil || e3 != nil || e4 != nil {
		return Fragment{}, ErrMalformedDatagram
	}
	f := Fragment{Kind: p[4], Counter: c, Reference: ref, Index: wireInt(p[7]), Count: wireInt(p[8]), Total: wireInt(p[9]), Tag: tag, Data: data}
	if !validFragment(f) {
		return Fragment{}, ErrMalformedDatagram
	}
	return f, nil
}
