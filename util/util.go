// Use of this source code is governed by a
// license that can be found in the LICENSE file.

package util

import (
	"golang.org/x/net/context"
	"net"

	"bytes"
	"container/list"
	"crypto/aes"
	"crypto/cipher"
	cr "crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log"
	mr "math/rand"
	"os"
	"sync"
	"time"
)

// Intended thread-safe
// A great absolutely magical library is here:
//           `go get github.com/hashicorp/golang-lru/`
type LRUCache struct {
	lock    sync.RWMutex
	MaxSize int
	items   map[interface{}]*list.Element
	root    *list.List
}

func NewLRU(max int) *LRUCache {
	l := &LRUCache{
		MaxSize: max,
		items:   make(map[interface{}]*list.Element),
		root:    list.New(),
	}

	return l
}

type entry struct {
	key   interface{}
	value interface{}
}

// Returns true if elems are added up to MaxSize
func (l *LRUCache) SetItem(key, value interface{}) bool {

	l.lock.Lock()
	defer l.lock.Unlock()

	if ent, ok := l.items[key]; ok {
		// Item exsits or blocked by size policy.
		l.root.MoveToFront(ent)
		ent.Value.(*entry).value = value
		return false
	}

	// Add new item
	e := &entry{key, value}
	_entry := l.root.PushFront(e)
	l.items[key] = _entry

	ok := l.root.Len() > l.MaxSize

	if ok {
		_e := l.root.Back()
		delete(l.items, _e.Value.(*entry).key)
		l.root.Remove(l.root.Back())
	}
	return ok
}

func (l *LRUCache) GetItem(key interface{}) interface{} {

	l.lock.Lock()
	defer l.lock.Unlock()

	if item, ok := l.items[key]; ok {
		l.root.MoveToFront(item)
		return item.Value.(*entry).value
	}

	return nil
}

func (l *LRUCache) Len() int {
	return len(l.items)
}

// ResolveName resolves domain names.
func ResolveName(host string, ctx context.Context, lru *LRUCache, pref bool) ([]net.IP, error) {

	r := DNSResolver(pref)

	// This is actually a very expensive task,
	// so let's lookup from cache
	if ip, ok := (lru.GetItem(host)).(net.IP); ok {
		ips := make([]net.IP, 1)
		ips[0] = ip
		return ips, nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	addrs, err := r.LookupIPAddr(ctx, host)
	ips := make([]net.IP, len(addrs))

	for i, ia := range addrs {
		// refer to the pointer...
		ips[i] = ia.IP
	}

	// failed to parse doamin?
	if len(ips) == 0 {
		return nil, errors.New("ResolveName: cannot parse doamin")
	}

	// Cache ip
	lru.SetItem(host, ips[0])

	if err != nil {
		return ips, nil
	}

	return ips, nil
}

// TODO:
//   hack go's default dns resolver
func DNSResolver(p bool) *net.Resolver {
	r := &net.Resolver{}
	switch p {
	case p:
		r.PreferGo = true
		r.StrictErrors = true
		break
	default:
		// Experimental!
		r.PreferGo = false
		r.StrictErrors = true
		r.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			ctx = context.Background()
			network = "udp"
			address = "8.8.8.8"
			return net.Dial(network, address)
		}
	}
	return r
}

func LookupIP(r *net.Resolver, ctx context.Context, host string) ([]net.IPAddr, error) {
	return r.LookupIPAddr(ctx, host)
}

type Config struct {
	Servers    []string `json:"servers"`
	ServerPort int      `json:"port"`
	ServerAddr string   `json:"address"`
	IsClient   bool     `json:"isclient"`
	IsServer   bool     `json:"isserver"`
	Method     string   `json:"method"`
	Password   string   `json:"password"`
	Logfile    string   `json:"logfile"`
	Verbose    int      `json:"verbose"`
	RunAs      string
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

	defer f.Close()

	data := make([]byte, 1024) /* File buffer for 1024 should be enough... */
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
		c.Logfile = "./rserver.log"
	}
	cpt := &Crypto{Password: c.Password, Method: c.Method}

	c.Encryption = cpt

	return c, nil
}

var methods = []struct {
	key           string
	keyLen, ivLen int
}{
	{"aes-128-cfb", 16, 16},
	{"aes-192-cfb", 24, 16},
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
			break
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

	if len(c.Password)%m.keyLen != 0 {
		pad := m.keyLen - len(c.Password)
		// get checksum
		sum := sha256.Sum256([]byte(c.Password))
		if err != nil {
			panic(err)
		}
		for i := 0; i < pad; i++ {
			c.Password += string(sum[i])
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

// Encrypt encrypts plaintext based on given key and key length.
// The size of plaintext should not be multiple of block size because
// of the padding.
func (c *Crypto) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return plaintext, nil
	}
	// padding..
	if len(plaintext)%aes.BlockSize != 0 {
		log.Println("padding")
		m := len(plaintext) % aes.BlockSize
		p := aes.BlockSize - m
		// get checksum
		sum := sha256.Sum256(plaintext)
		for i := 0; i < p; i++ {
			plaintext = append(plaintext, sum[i])
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

// Decrypt decrypts ciphertext into plaintext
// The size ciphertext must be a multiple of the block size.
// Otherwise padding will put on plaintext and doesn't much.
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
