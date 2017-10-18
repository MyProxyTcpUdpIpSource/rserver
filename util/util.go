// Use of this source code is governed by a
// license that can be found in the LICENSE file.

package util

import (
	"golang.org/x/net/context"
	"net"

	"bytes"
	"crypto/aes"
	"crypto/cipher"
	cr "crypto/rand"
	"errors"
	"io"
	"os"
	"encoding/json"
	mr "math/rand"
	"time"
)

var Servers = []string{"8.8.8.8", "8.8.4.4"}

// DnsResolver resolves domain names.
func DnsResolver(host string, ctx context.Context) ([]net.IP, error) {

	var ips []net.IP

	ips, err := net.LookupIP(host)
	
	// failed to parse doamin?
	if len(ips) == 0 {
		return nil, errors.New("DnsResolver: cannot parse doamin")
	}
	
	if err != nil {
		return ips, nil
	}

	if ctx == nil {
		ctx = context.Background()
	}
	return ips, nil
}

func DNSResolver(p bool) *net.Resolver {
	r := &net.Resolver{}
	switch (p) {
	case p:
		r.PreferGo = true
		r.StrictErrors = true
	}
	return r
}

func LookupIP(r *net.Resolver, ctx context.Context, host string) ([]net.IPAddr, error){
	return r.LookupIPAddr(ctx, host)
}

type Config struct {
	Servers   []string `json:"servers"`
	ServerPort int `json:"port"`
	ServerAddr string `json:"address"`
	IsClient bool `json:"isclient"`
	IsServer bool `json:"isserver"`
	Method string `json:"method"`
	Password string `json:"password"`
	Logfile string `json:"logfile"`
	Verbose int `json:"verbose"`
	RunAs string
	Encryption *Crypto
}

func (c *Config) GetAServer() string {
	if len(c.Servers) == 0 {
		return ""
	}
	src := mr.NewSource(time.Now().UnixNano())
	r := mr.New(src)
	return c.Servers[r.Intn(len(c.Servers))]
}

func GetConf(path string) (*Config, error) {

	c := &Config{}

	f, err := os.OpenFile(path, os.O_RDONLY, 0600)
	if err != nil {
		return nil, nil
	}

	data := make([]byte, 1024)
	n, err := f.Read(data)
	if err != nil {
		panic(err)
	}
	data = data[:n]
	
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	// avoid 'no such file or directory error'
	if c.Logfile == "" {
		c.Logfile = "/var/log/rserver.log"
	}
	cpt := &Crypto{Password: c.Password, Method: c.Method}
	
	c.Encryption = cpt
	
	return c, nil
}

var methods = []struct {
	key           string
	keyLen, ivLen int
}{
	{"aes-192-cfb", 24, 16},
	{"aes-128-cfb", 16, 16},
	{"aes-256-cfb", 32, 16},
}

type method struct {
	key    string
	keyLen int
	ivLen  int
}

type Crypto struct {
	Password string `json:"password"`
	Method   string `json:"method"`
}

func GetMethodInfo(s string) (*method, error) {

	m := &method{}

	for _, ms := range methods {
		switch {
		case ms.key == s:
			m.key = ms.key
			m.keyLen = ms.keyLen
			m.ivLen = ms.ivLen
		}
	}
	if m == nil {
		return nil, errors.New("Method not supported")
	}
	return m, nil
}

func (c *Crypto) GetCipher() (cipher.Block, error) {
	m, err := GetMethodInfo(c.Method)

	if err != nil {
		return nil, err
	}

	// in case password length less than keyLen
	// TODO: better way to padding here
	if len(c.Password) < m.keyLen {
		pad := m.keyLen - len(c.Password)
		for i := 0; i < pad; i++ {
			c.Password +=" "
		}
	}
	var key []byte
	buf := bytes.NewBuffer(key)
	i := 0
	for {
		if m.keyLen-1 < len(buf.Bytes()) {
			break
		}
		err := buf.WriteByte([]byte(c.Password)[i])
		if err != nil {
			return nil, err
		}
		i++
	}
	return aes.NewCipher(buf.Bytes())
}

func (c *Crypto) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return plaintext, nil
	}
	// padding..
	if len(plaintext)%aes.BlockSize != 0 {
		m := len(plaintext) % aes.BlockSize
		p := aes.BlockSize - m
		for i := 0; i < p; i++ {
			plaintext = append(plaintext, 0x0)
		}
	}

	m, err := GetMethodInfo(c.Method)

	if err != nil {
		return nil, err
	}
	block, err := c.GetCipher()
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, m.ivLen+len(plaintext))
	iv := ciphertext[:m.ivLen]

	if _, err := io.ReadFull(cr.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

func (c *Crypto) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	m, err := GetMethodInfo(c.Method)

	if err != nil {
		return nil, err
	}

	block, err := c.GetCipher()
	if err != nil {
		return nil, err
	}

	iv := ciphertext[:m.ivLen]
	ciphertext = ciphertext[m.ivLen:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("wrong ciphertext")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	return ciphertext, nil
}
