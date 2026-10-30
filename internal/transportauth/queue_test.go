package transportauth

import "testing"

func TestPacketQueueCountBoundAndDropNewest(t *testing.T) {
	var q PacketQueue[int]
	for i := 0; i < MaxInboundPackets; i++ {
		if !q.Push(i, 1) {
			t.Fatal("queue filled early")
		}
	}
	if q.Push(999, 1) {
		t.Fatal("packet count overflow accepted")
	}
	for i, value := range q.Drain(0) {
		if value != i {
			t.Fatal("overflow replaced an earlier packet")
		}
	}
	stats := q.Stats()
	if stats.Packets != 0 || stats.Bytes != 0 || stats.OverflowPackets != 1 || stats.PeakPackets != MaxInboundPackets {
		t.Fatal("incorrect count statistics")
	}
}

func TestPacketQueueByteBoundAndReferenceRelease(t *testing.T) {
	var q PacketQueue[[]byte]
	for i := 0; i < MaxInboundBytes/4096; i++ {
		if !q.Push(make([]byte, 4096), 4096) {
			t.Fatal("byte limit filled early")
		}
	}
	if q.Push(make([]byte, 4096), 4096) {
		t.Fatal("byte overflow accepted")
	}
	if len(q.Drain(1)) != 1 || !q.Push(make([]byte, 4096), 4096) {
		t.Fatal("drain did not free byte budget")
	}
	q.Drain(0)
	for _, payload := range q.slots {
		if payload != nil {
			t.Fatal("drained slot retained a payload")
		}
	}
	stats := q.Stats()
	if stats.Bytes != 0 || stats.Packets != 0 || stats.PeakBytes != MaxInboundBytes || stats.OverflowBytes != 4096 {
		t.Fatal("incorrect byte statistics")
	}
	if q.Push(make([]byte, MaxInboundBytes+1), MaxInboundBytes+1) {
		t.Fatal("single oversized packet accepted")
	}
	if q.Stats().Bytes != 0 {
		t.Fatal("oversized packet retained")
	}
}

func TestPacketQueuePruneAcrossRingWrap(t *testing.T) {
	type entry struct {
		id      int
		payload []byte
	}
	var q PacketQueue[entry]
	for i := 0; i < MaxInboundPackets; i++ {
		q.Push(entry{i, make([]byte, 4)}, 4)
	}
	q.Drain(200)
	for i := 0; i < 200; i++ {
		if !q.Push(entry{500 + i, make([]byte, 4)}, 4) {
			t.Fatal("wrapped queue filled early")
		}
	}
	q.Prune(func(e entry) bool { return e.id%2 == 0 })
	expected := []int{}
	for i := 200; i < MaxInboundPackets; i++ {
		if i%2 == 0 {
			expected = append(expected, i)
		}
	}
	for i := 500; i < 700; i++ {
		if i%2 == 0 {
			expected = append(expected, i)
		}
	}
	actual := q.Drain(0)
	if len(actual) != len(expected) {
		t.Fatal("prune lost valid packets")
	}
	for i, e := range actual {
		if e.id != expected[i] {
			t.Fatal("prune changed FIFO order")
		}
	}
	for _, e := range q.slots {
		if e.payload != nil {
			t.Fatal("prune/drain retained payload reference")
		}
	}
	stats := q.Stats()
	if stats.PurgedPackets != 128 || stats.Bytes != 0 || stats.Packets != 0 {
		t.Fatal("prune byte budget incorrect")
	}
}
