package transportauth

const MaxInboundPackets = 256
const MaxInboundBytes = 256 << 10

type QueueStats struct {
	Packets         int    `json:"packets"`
	Bytes           int    `json:"bytes"`
	PeakPackets     int    `json:"peakPackets"`
	PeakBytes       int    `json:"peakBytes"`
	OverflowPackets uint64 `json:"overflowPackets"`
	OverflowBytes   uint64 `json:"overflowBytes"`
	PurgedPackets   uint64 `json:"purgedPackets"`
}

// PacketQueue is a fixed-size FIFO, protected by its owning listener's lock.
// Overflow drops the new packet. Removed slots are zeroed to release payloads.
type PacketQueue[T any] struct {
	slots              [MaxInboundPackets]T
	sizes              [MaxInboundPackets]int
	head, count, bytes int
	stats              QueueStats
}

func (q *PacketQueue[T]) Push(value T, size int) bool {
	if size < 0 {
		return false
	}
	if q.count == MaxInboundPackets || size > MaxInboundBytes-q.bytes {
		q.stats.OverflowPackets++
		q.stats.OverflowBytes += uint64(size)
		return false
	}
	q.push(value, size)
	return true
}

func (q *PacketQueue[T]) push(value T, size int) {
	index := (q.head + q.count) % MaxInboundPackets
	q.slots[index], q.sizes[index] = value, size
	q.count++
	q.bytes += size
	if q.count > q.stats.PeakPackets {
		q.stats.PeakPackets = q.count
	}
	if q.bytes > q.stats.PeakBytes {
		q.stats.PeakBytes = q.bytes
	}
}

func (q *PacketQueue[T]) pop() (T, int) {
	value, size := q.slots[q.head], q.sizes[q.head]
	var zero T
	q.slots[q.head] = zero
	q.sizes[q.head] = 0
	q.head = (q.head + 1) % MaxInboundPackets
	q.count--
	q.bytes -= size
	if q.count == 0 {
		q.head = 0
	}
	return value, size
}

func (q *PacketQueue[T]) Drain(limit int) []T {
	if limit <= 0 || limit > q.count {
		limit = q.count
	}
	if limit == 0 {
		return nil
	}
	result := make([]T, 0, limit)
	for i := 0; i < limit; i++ {
		value, _ := q.pop()
		result = append(result, value)
	}
	return result
}

func (q *PacketQueue[T]) Prune(keep func(T) bool) {
	count := q.count
	for i := 0; i < count; i++ {
		value, size := q.pop()
		if keep(value) {
			q.push(value, size)
		} else {
			q.stats.PurgedPackets++
		}
	}
}

func (q *PacketQueue[T]) Stats() QueueStats {
	stats := q.stats
	stats.Packets = q.count
	stats.Bytes = q.bytes
	return stats
}
