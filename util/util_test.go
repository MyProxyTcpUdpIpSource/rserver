package util

import (
	"context"
	"testing"
	"bytes"
)

var hosts = []string{
	"google.com",
	"posteo.de",
	"httpbin.org",
}

func TestResolver(t *testing.T) {
	for _, h := range hosts {
		ips, er := ResolveName(h, context.Background())
		if er != nil {
			t.Fatal(er)
		}
		t.Logf("%s ips: %v", h, ips)
	}
}

var cryptoData = []Crypto{
	{"I like your shirt.", "aes-128-cfb"},
	{"A party at which only losers showed up.", "aes-192-cfb"},
	{"Believe me I'm having such a wonderful day.", "aes-256-cfb"},
	{"Dolphins can change a diaper under water.", "aes-256-cfb"},
	{"wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww", "aes-256-cfb"},	
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
	// notice the size of plaintext is 64 bytes
	plaintext := []byte("I think I should be more discrete and fly over Paris tomorrow...")
	_plaintext := make([]byte, len(plaintext))
	copy(_plaintext, plaintext)
	crypt := &Crypto{"this-is-insecure-password", "aes-256-cfb"}
	ciphertext, _ := crypt.Encrypt(plaintext)
	text, _ := crypt.Decrypt(ciphertext)

	if !(bytes.Equal(_plaintext, text)) {
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

// Cache test
var cacheData = []string{
	"a", "b", "c",
}

func TestCache(t *testing.T) {
	cache := &LRUCache{}
	cache.SetItem("key", "value")
	t.Log(cache.start)
	t.Log(cache.GetItem("key"))
}
