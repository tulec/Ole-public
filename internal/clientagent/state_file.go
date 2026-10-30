package clientagent

import (
	"hash/fnv"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// Bounded lock storage, shared by StateStore instances targeting the same path.
// This also avoids Windows rename failures from our own open readers.
var stateFileLocks [64]sync.RWMutex

func stateFileLock(path string) *sync.RWMutex {
	if absolute, err := filepath.Abs(path); err == nil {
		path = absolute
	}
	path = filepath.Clean(path)
	if runtime.GOOS == "windows" {
		path = strings.ToLower(path)
	}
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(path))
	return &stateFileLocks[hash.Sum32()%uint32(len(stateFileLocks))]
}

// Write alongside the destination, then replace it only after a complete,
// flushed write. A failed write/rename leaves the previous state intact.
func replaceStateFile(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".ole-state-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}
