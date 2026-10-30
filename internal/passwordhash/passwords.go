// Package passwordhash stores Argon2id PHC strings and verifies legacy SHA256.
package passwordhash

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	MemoryKiB   uint32 = 19 * 1024
	Iterations  uint32 = 2
	Parallelism uint8  = 1
	saltBytes          = 16
	keyBytes           = 32
)

func Hash(password string) (string, error) {
	if password == "" {
		return "", errors.New("password is required")
	}
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, Iterations, MemoryKiB, Parallelism, keyBytes)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, MemoryKiB, Iterations, Parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify returns whether the password matches and whether it needs a policy
// upgrade. Reject malformed/unbounded PHC parameters before allocating memory.
func Verify(password, encoded string) (matches, needsUpgrade bool) {
	if password == "" {
		return false, false
	}
	if len(encoded) == 64 {
		legacy, err := hex.DecodeString(encoded)
		if err != nil {
			return false, false
		}
		sum := sha256.Sum256([]byte(password))
		matches = subtle.ConstantTimeCompare(sum[:], legacy) == 1
		return matches, matches
	}
	if len(encoded) > 256 || strings.ContainsAny(encoded, "\r\n") {
		return false, false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false, false
	}
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return false, false
	}
	values := [3]uint64{}
	for i, name := range []string{"m=", "t=", "p="} {
		if !strings.HasPrefix(params[i], name) {
			return false, false
		}
		value, err := strconv.ParseUint(strings.TrimPrefix(params[i], name), 10, 32)
		if err != nil {
			return false, false
		}
		values[i] = value
	}
	memory, iterations, threads := values[0], values[1], values[2]
	if threads < 1 || threads > 4 || memory < 8*threads || memory > 64*1024 || iterations < 1 || iterations > 10 {
		return false, false
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < saltBytes || len(salt) > 64 {
		return false, false
	}
	expected, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(expected) != keyBytes {
		return false, false
	}
	actual := argon2.IDKey([]byte(password), salt, uint32(iterations), uint32(memory), uint8(threads), keyBytes)
	matches = subtle.ConstantTimeCompare(actual, expected) == 1
	return matches, matches && (memory < uint64(MemoryKiB) || iterations < uint64(Iterations))
}
