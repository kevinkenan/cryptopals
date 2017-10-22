package main

import (
	"bytes"
	"fmt"
	"errors"
	"strings"
	"crypto/rand"

	"github.com/kevinkenan/cryptopals/utils"
)

func s2c13() {
	fmt.Println("Set 2, Challenge 13")

	// Generate a random key.
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		fmt.Println(err)
		return
	}

	o := c13oracle{key}

	// Get a block of 16 bytes of padding.
	b, _ := o.encryptedProfileFor("xxxxxxxxx")
	// Blocks:
	//   email=xxxxxxxxx&
	//   uid=10&role=user
	// We want the 3rd block of just padding.
	fullBlockPadding := b[len(b)-16:]

	// Get a block beginning with "email" and another that begins with
	// "admin".
	b, _ = o.encryptedProfileFor("test@1234.admin")
	// Blocks:
	//   email=test@1234.
	//   admin&uid=19&rol
	//   e=user
	// We want the 1st and 2nd blocks. 
	emailBlock := b[0:16]
	adminBlock := b[16:32]
	s, _ := o.decryptProfileCookie(bytes.Join([][]byte{adminBlock,fullBlockPadding}, []byte{}))

	// Get a block that ends with "role=" and wraps up the email address.
	b, _ = o.encryptedProfileFor("xxxxxxxxxxcom")
	// Blocks:
	//   email=xxxxxxxxxx
	//   com&uid=10&role=
	//   user
	// We want the 2nd block.
	roleBlock := b[16:32]

	// Assemble the blocks into a new ciphertext.
	newCiphertext := bytes.Join([][]byte{emailBlock, roleBlock, adminBlock, emailBlock, fullBlockPadding}, []byte{})

	// Decrypt the constructed ciphertext.
	s, _ = o.decryptProfileCookie(newCiphertext)

	// Build a new profile with the decrypted construction.
	profile := parseProfileString(s)

	if profile.role == "admin" {
		cryptopals.PrintSuccess(profile.role)
	} else {
		cryptopals.PrintFailure("")
	}
}

type c13oracle struct {
	key []byte
}

func (o c13oracle) encryptedProfileFor(email string) ([]byte, error) {
	if strings.ContainsAny(email, "&=") {
		return nil, errors.New("invalid characters in email")
	}
	profile := userProfile{email: email, uid: "10", role: "user"}
	cookie := profile.getCookie()

	ciphertext, err := cryptopals.EncryptAESwithECB(cryptopals.Padding([]byte(cookie), 16), o.key)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func (o c13oracle) decryptProfileCookie(profile []byte) (string, error) {
	plaintext, err := cryptopals.DecryptAESwithECB(profile, o.key)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// A simple user profile struct.
type userProfile struct {
	email, uid, role string
}

// Turn a userProfile struct into a cookie string:
//   email=foo@bar.com&uid=27&role=user
func (p userProfile) getCookie() string {
	var cookieBuffer bytes.Buffer
	cookieBuffer.WriteString("email=")
	cookieBuffer.WriteString(p.email)
	cookieBuffer.WriteString("&uid=")
	cookieBuffer.WriteString(p.uid)
	cookieBuffer.WriteString("&role=")
	cookieBuffer.WriteString(p.role)

	return cookieBuffer.String()
}

// Turn a userProfile cookie string back into a userProfile struct.
func parseProfileString(s string) userProfile {
	kvPairs := strings.Split(s, "&")
	if kvPairs[0] == "" {
		return userProfile{}
	}

	kvmap := map[string]string{}
	for _, kv := range kvPairs {
		e := strings.Split(kv, "=")
		kvmap[e[0]] = e[1]
	}

	profile := userProfile{}
	profile.email = kvmap["email"]
	profile.uid = kvmap["uid"]
	profile.role = kvmap["role"]

	return profile
}