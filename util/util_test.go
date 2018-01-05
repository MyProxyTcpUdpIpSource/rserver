package util

import (
	"bytes"
	"context"
	"testing"
)

var hosts = []string{
	"google.com",
	"posteo.de",
	"httpbin.org",
}

func TestResolver(t *testing.T) {
	lru := NewLRU(100)
	for _, h := range hosts {
		_, er := ResolveName(h, context.Background(), lru, true)
		if er != nil {
			t.Fatal(er)
		}
		// this may not work under some firewall policy
		fromGoogle, er := ResolveName(h, context.Background(), lru, false)
		if er != nil {
			t.Fatal(er)
		}
		t.Log(fromGoogle)
	}
}

var cryptoData = []Crypto{
	{"I like your shirt.", "aes-128-cfb"},
	{"A party at which only losers showed up.", "aes-192-cfb"},
	{"Believe me I'm having such a wonderful day.", "aes-256-cfb"},
	{"Dolphins can change a diaper under water.", "aes-256-cfb"},
	{"wwwwwwwwwwwwwwwwwwwww", "aes-256-cfb"},
}

func TestGetMethod(t *testing.T) {
	for _, m := range cryptoData {
		if mtd, err := GetMethodInfo(m.Method); err != nil {
			t.Error(err)
		} else {
			t.Log(mtd)
		}
	}

	stupid := Crypto{"I like your shirt.", "stupid-method"}
	if m, _ := GetMethodInfo(stupid.Method); m != nil {
		t.Log(m)
	} else {
		t.Error("method not supported")
	}

}

func TestGetCipher(t *testing.T) {

	for _, c := range cryptoData {
		if block, err := c.GetCipher(); err != nil {
			t.Error(err)
		} else {
			t.Log(block)
		}
	}

}

var testData = []string{
	"I wish I could fly like a bird.",
	"You have such a wonderful personality",
	"I love Japan and I told you a lie",
	"A problem with me being Japanese.",
	"I like cats over dogs",
}

func TestEncrypt(t *testing.T) {
	for _, c := range cryptoData {
		for _, msg := range testData {
			if _, e := c.Encrypt([]byte(msg)); e != nil {
				t.Error(e)
			}
		}
	}
	c := &Crypto{"I like your shirt.", "aes-128-cfb"}
	conf := &Config{}
	conf.Encryption = c
	d := []byte{5, 0, 0, 3, 24, 100, 101, 116, 101, 99, 116, 112, 111, 114, 116, 97, 108, 46, 102, 105, 114, 101, 102, 111, 120, 46, 99, 111, 109, 0, 80}
	if _, e := conf.Encryption.Encrypt(d); e != nil {
		t.Error(e)
	}
}

func TestDecrypt(t *testing.T) {
	data := []byte{
		206, 172, 215, 137, 0, 70, 123, 124, 231, 242,
		179, 215, 148, 183, 64, 78, 176, 236, 0, 153,
		72, 186, 52, 224, 123, 182, 137, 207, 143, 85,
		243, 247, 161, 46, 35, 184, 6, 70, 115, 147, 76,
		180, 27, 41, 177, 188, 71, 116, 145, 109, 228, 211,
		60, 198, 98, 132, 92, 6, 162, 153, 103, 187, 195, 77}
	c := &Crypto{"I'm-having-an-existential-crisis.", "aes-256-cfb"}
	if d, err := c.Decrypt(data); err != nil {
		t.Error(err)
	} else {
		t.Log(d)
	}
}

func TestEncryptAndDecrypt(t *testing.T) {
	p1 := []byte("I think I should be more discrete and fly over Paris!")

	p2 := make([]byte, len(p1))

	copy(p2, p1)

	crypt := &Crypto{"this-is-insecure-password", "aes-256-cfb"}

	ciphertext, _ := crypt.Encrypt(p1)

	text, _ := crypt.Decrypt(ciphertext)

	out := make([]byte, len(p1))

	copy(out, text)

	if !(bytes.Equal(p2, out)) {
		t.Error("doesn't match")
	}
}

func TestGetAServer(t *testing.T) {
	conf := &Config{
		Servers: []string{
			"0.0.0.0:1080",
			"1.1.1.1:1080",
			"8.8.8.8:1080",
			"45.32.211.3:1080",
			"5.2.11.4:1080",
		},
	}
	s := conf.GetAServer()
	if s == "" {
		t.Error("cannot get a server")
	}
	t.Log(s)
}

var items = []struct {
	key   string
	value string
}{
	{"key1", "value1"}, // oldest item
	{"key2", "value2"},
	{"key3", "value3"},
	{"key4", "value4"},
	{"key5", "value5"}, // latest item
}

func TestSetItems(t *testing.T) {

	var elem = struct {
		key   string
		value string
	}{
		"thisKey", "thisValue",
	}

	var anotherElem = struct {
		key   string
		value string
	}{
		"anotherKey", "anotherValue",
	}

	cache := NewLRU(2) // Cannot go up to 2 elements

	if ok := cache.SetItem(elem.key, elem.value); ok {
		t.Fatal("SetItem")
	}

	// Duplicated items are not allowed to exist.
	cache.SetItem(elem.key, elem.value)
	if !(cache.Len() == 1) {
		t.Fatal("SetItem")
	}

	if ok := cache.SetItem(anotherElem.key, anotherElem.value); ok {
		t.Fatal("SetItem anotherelem")
	}

	// Up to 3 elems, and then last elem will be removed
	cache.SetItem(items[1].key, items[1].value)

	// Oldest items should have been removed
	if !(cache.GetItem(elem.key) == nil) {
		t.Fatal("thisKey should've been removed!")
	}
}

func TestGetItems(t *testing.T) {
	c := NewLRU(5)
	for i := 0; i < 5; i++ {
		ite := items[i]
		c.SetItem(ite.key, ite.value)
	}
	if c.GetItem(items[1].key) == nil {
		t.Fatal("GetItem")
	}
}
