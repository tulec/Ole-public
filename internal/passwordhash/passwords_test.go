package passwordhash

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestPasswordRoundTripPreservesLongUnicodeAndWhitespace(t *testing.T) {
	password := " " + strings.Repeat("пароль", 20) + "\x00tail "
	hash, err := Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	if valid, upgrade := Verify(password, hash); !valid || upgrade {
		t.Fatal("current password rejected or marked legacy")
	}
	for _, wrong := range []string{password[:72], strings.TrimSpace(password), password + "wrong", ""} {
		if valid, upgrade := Verify(wrong, hash); valid || upgrade {
			t.Fatal("different password accepted")
		}
	}
	if encoded, err := Hash(""); encoded != "" || err == nil {
		t.Fatal("empty password hashed")
	}
}

func TestPasswordVerifierRejectsMalformedAndUnboundedHashes(t *testing.T) {
	hash, err := Hash("secret")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(hash, "$")
	for _, invalid := range []string{
		"", "hash", strings.Repeat("g", 64), strings.Repeat("a", 257),
		strings.Replace(hash, "argon2id", "argon2i", 1),
		strings.Replace(hash, "v=19", "v=16", 1),
		strings.Replace(hash, "m=19456", "m=0", 1),
		strings.Replace(hash, "m=19456", "m=65537", 1),
		strings.Replace(hash, "m=19456", "m=4294967296", 1),
		strings.Replace(hash, "t=2", "t=0", 1),
		strings.Replace(hash, "t=2", "t=11", 1),
		strings.Replace(hash, "p=1", "p=0", 1),
		strings.Replace(hash, "p=1", "p=5", 1),
		strings.Replace(hash, "m=19456", "m=7", 1),
		strings.Replace(hash, "m=19456", "m=-1", 1),
		strings.Replace(hash, "p=1", "p=1junk", 1),
		strings.Replace(hash, "m=19456,t=2,p=1", "t=2,m=19456,p=1", 1),
		strings.Replace(hash, "p=1", "p=1,x=1", 1),
		strings.Replace(hash, parts[4], "bad-salt", 1),
		strings.Replace(hash, parts[5], "bad-key", 1),
		hash + "$extra", hash + "\n",
	} {
		if valid, upgrade := Verify("secret", invalid); valid || upgrade {
			t.Error("malformed/unbounded hash accepted")
		}
	}
}

func TestLegacyAndWeakerArgon2NeedUpgrade(t *testing.T) {
	sum := sha256.Sum256([]byte("secret"))
	for _, hash := range []string{hex.EncodeToString(sum[:]), strings.ToUpper(hex.EncodeToString(sum[:]))} {
		if valid, upgrade := Verify("secret", hash); !valid || !upgrade {
			t.Fatal("legacy password not marked for upgrade")
		}
		if valid, upgrade := Verify("wrong", hash); valid || upgrade {
			t.Fatal("wrong legacy password accepted")
		}
	}
	salt := []byte("0123456789abcdef")
	key := argon2.IDKey([]byte("secret"), salt, 1, 8, 1, keyBytes)
	weak := fmt.Sprintf("$argon2id$v=19$m=8,t=1,p=1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
	if valid, upgrade := Verify("secret", weak); !valid || !upgrade {
		t.Fatal("weaker Argon2 password not marked for upgrade")
	}
}

func BenchmarkHash(b *testing.B) {
	b.ReportAllocs()
	b.ReportMetric(float64(MemoryKiB)/1024, "MiB/workspace")
	for range b.N {
		if _, err := Hash("benchmark password"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	hash, err := Hash("benchmark password")
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		if valid, _ := Verify("benchmark password", hash); !valid {
			b.Fatal("verification failed")
		}
	}
}

func BenchmarkLegacySHA256Verify(b *testing.B) {
	sum := sha256.Sum256([]byte("benchmark password"))
	hash := hex.EncodeToString(sum[:])
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if valid, _ := Verify("benchmark password", hash); !valid {
			b.Fatal("legacy verification failed")
		}
	}
}
