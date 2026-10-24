package consumer

import (
	"crypto/rand"
	"os"
	"testing"

	crypto11 "github.com/ad3n/crypto/v2"
	pkcs11 "github.com/ad3n/pkcs11-go/cryptoki"
)

func TestForkAttributeCompatibility(t *testing.T) {
	var attribute *crypto11.Attribute = pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, uint(pkcs11.CKK_AES))
	if pkcs11.BytesToULong(attribute.Value) != pkcs11.CKK_AES {
		t.Fatal("incorrect attribute encoding")
	}
}

func TestConsumerLookup(t *testing.T) {
	config := os.Getenv("CRYPTO11_CONSUMER_CONFIG")
	if config == "" {
		t.Skip("CRYPTO11_CONSUMER_CONFIG must identify an isolated writable test token")
	}

	ctx, err := crypto11.ConfigureFromFile(config)
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Close()

	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}

	key, err := ctx.GenerateSecretKey(id, 128, crypto11.CipherAES)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := key.Delete(); err != nil {
			t.Error(err)
		}
	}()

	found, err := ctx.FindKey(id, nil)
	if err != nil || found == nil {
		t.Fatalf("FindKey: %v, %v", found, err)
	}

	keys, err := ctx.FindKeys(id, nil)
	if err != nil || len(keys) != 1 {
		t.Fatalf("FindKeys: count %d, error %v", len(keys), err)
	}
}
