package selfupdate

import (
	"encoding/base64"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"

	"golang.org/x/crypto/ed25519"
)

type Verifier struct {
	publicKey publicKey
	signature signature
}

type publicKey struct {
	SignatureAlgorithm [2]byte
	KeyID              [8]byte
	Key                [32]byte
}

type signature struct {
	UntrustedComment   string
	SignatureAlgorithm [2]byte
	KeyID              [8]byte
	Signature          [64]byte
	TrustedComment     string
	GlobalSignature    [64]byte
}

func parsePublicKey(publicKeyStr string) (publicKey, error) {
	var pkey publicKey
	bin, err := base64.StdEncoding.DecodeString(publicKeyStr)
	if err != nil || len(bin) != 42 {
		return pkey, errors.New("Invalid encoded public key")
	}
	copy(pkey.SignatureAlgorithm[:], bin[0:2])
	copy(pkey.KeyID[:], bin[2:10])
	copy(pkey.Key[:], bin[10:42])
	return pkey, nil
}

func decodeSignature(in string) (signature, error) {
	var sign signature
	lines := strings.SplitN(in, "\n", 4)
	if len(lines) < 4 {
		return sign, errors.New("Incomplete encoded signature")
	}
	sign.UntrustedComment = lines[0]
	bin1, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil || len(bin1) != 74 {
		return sign, errors.New("Invalid encoded signature")
	}
	sign.TrustedComment = lines[2]
	bin2, err := base64.StdEncoding.DecodeString(lines[3])
	if err != nil || len(bin2) != 64 {
		return sign, errors.New("Invalid encoded signature")
	}
	copy(sign.SignatureAlgorithm[:], bin1[0:2])
	copy(sign.KeyID[:], bin1[2:10])
	copy(sign.Signature[:], bin1[10:74])
	copy(sign.GlobalSignature[:], bin2)
	return sign, nil
}

func parseSignatureFromURL(url string, transport http.RoundTripper) (signature, error) {
	var sign signature
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return sign, err
	}
	client := &http.Client{Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		return sign, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return sign, errors.New(resp.Status)
	}
	bin, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return sign, err
	}
	return decodeSignature(string(bin))
}

func parseSignatureFromFile(file string) (signature, error) {
	bin, err := ioutil.ReadFile(file)
	if err != nil {
		return signature{}, err
	}
	return decodeSignature(string(bin))
}

func (v *Verifier) LoadFromURL(signatureURL string, passphrase string, transport http.RoundTripper) error {
	pkey, err := parsePublicKey(passphrase)
	if err != nil {
		return err
	}
	v.publicKey = pkey

	sign, err := parseSignatureFromURL(signatureURL, transport)
	if err != nil {
		return err
	}

	v.signature = sign
	return nil
}

func (v *Verifier) LoadFromFile(signaturePath string, passphrase string) error {
	pkey, err := parsePublicKey(passphrase)
	if err != nil {
		return err
	}
	v.publicKey = pkey

	sign, err := parseSignatureFromFile(signaturePath)
	if err != nil {
		return err
	}

	v.signature = sign
	return nil
}

func NewVerifier() *Verifier {
	return &Verifier{}
}

func (v *Verifier) Verify(bin []byte) error {
	if v.publicKey.SignatureAlgorithm != v.signature.SignatureAlgorithm {
		return errors.New("Incompatible signature algorithm")
	}
	if v.signature.SignatureAlgorithm[0] != 0x45 || v.signature.SignatureAlgorithm[1] != 0x64 {
		return errors.New("Unsupported signature algorithm")
	}
	if v.publicKey.KeyID != v.signature.KeyID {
		return errors.New("Incompatible key identifiers")
	}
	if !strings.HasPrefix(v.signature.TrustedComment, "trusted comment: ") {
		return errors.New("Unexpected format for the trusted comment")
	}
	if !ed25519.Verify(ed25519.PublicKey(v.publicKey.Key[:]), bin, v.signature.Signature[:]) {
		return errors.New("Invalid signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(v.publicKey.Key[:]),
		append(v.signature.Signature[:],
			[]byte(v.signature.TrustedComment)[17:]...),
		v.signature.GlobalSignature[:]) {
		return errors.New("Invalid global signature")
	}
	return nil
}
