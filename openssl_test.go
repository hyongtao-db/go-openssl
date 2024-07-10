package openssl

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testPassphrase = "z4yH36a6zerhfE5427ZV" //#nosec G101 -- Is hardcoded passphrase but only for testing purposes
	testPlaintext  = "hallowelt"
)

var testTable = []struct {
	tName    string
	tMdParam string
	tMdFunc  CredsGenerator
	tPBKDF   bool
}{
	// {"MD5", "md5", BytesToKeyMD5, false},
	// {"SHA1", "sha1", BytesToKeySHA1, false},
	// {"SHA256", "sha256", BytesToKeySHA256, false},
	// {"SHA384", "sha384", BytesToKeySHA384, false},
	// {"SHA512", "sha512", BytesToKeySHA512, false},
	// {"PBKDF2_MD5", "md5", PBKDF2MD5, true},
	// {"PBKDF2_SHA1", "sha1", PBKDF2SHA1, true},
	{"PBKDF2_SHA256", "sha256", PBKDF2SHA256, true},
	// {"PBKDF2_SHA384", "sha384", PBKDF2SHA384, true},
	// {"PBKDF2_SHA512", "sha512", PBKDF2SHA512, true},
}

func TestBinaryEncryptToDecryptWithCustomSalt(t *testing.T) {
	salt := []byte("saltsalt")

	o := New()

	enc, err := o.EncryptBinaryBytesWithSaltAndDigestFunc(testPassphrase, salt, []byte(testPlaintext), BytesToKeySHA256)
	require.NoError(t, err)

	dec, err := o.DecryptBinaryBytes(testPassphrase, enc, BytesToKeySHA256)
	require.NoError(t, err)

	assert.Equal(t, testPlaintext, string(dec))
}

func TestBinaryEncryptToDecrypt(t *testing.T) {
	o := New()

	enc, err := o.EncryptBinaryBytes(testPassphrase, []byte(testPlaintext), BytesToKeySHA256)
	require.NoError(t, err)

	dec, err := o.DecryptBinaryBytes(testPassphrase, enc, BytesToKeySHA256)
	require.NoError(t, err)

	assert.Equal(t, testPlaintext, string(dec))
}

func TestBinaryEncryptToOpenSSL(t *testing.T) {
	o := New()

	for _, tc := range testTable {
		t.Run(tc.tName, func(t *testing.T) {
			salt, err := o.GenerateSalt()
			require.NoError(t, err)

			enc, err := o.EncryptBinaryBytesWithSaltAndDigestFunc(testPassphrase, salt, []byte(testPlaintext), tc.tMdFunc)
			require.NoError(t, err)

			// Need to specify /dev/stdin as file so that we can pass in binary
			// data to openssl without creating a file
			cmdArgs := []string{
				"openssl", "aes-256-cbc",
				"-d",
				"-pass", fmt.Sprintf("pass:%s", testPassphrase),
				"-md", tc.tMdParam,
				"-in", "/dev/stdin",
			}

			if tc.tPBKDF {
				cmdArgs = append(cmdArgs, "-pbkdf2")
			}

			cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...) //#nosec:G204 -- Hardcoded tests, this is fine

			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stdin = bytes.NewBuffer(enc)

			err = cmd.Run()
			require.NoError(t, err)

			assert.Equal(t, testPlaintext, out.String())
		})
	}
}

func TestBinaryEncryptWithSaltShouldHaveSameOutput(t *testing.T) {
	plaintext := "outputshouldbesame"
	passphrase := "passphrasesupersecure"
	salt := []byte("saltsalt")

	o := New()

	enc1, err := o.EncryptBinaryBytesWithSaltAndDigestFunc(passphrase, salt, []byte(plaintext), BytesToKeySHA256)
	require.NoError(t, err)

	enc2, err := o.EncryptBinaryBytesWithSaltAndDigestFunc(passphrase, salt, []byte(plaintext), BytesToKeySHA256)
	require.NoError(t, err)

	assert.Equal(t, enc1, enc2)
}

func TestDecryptBinaryFromString(t *testing.T) {
	o := New()

	for _, tc := range testTable {
		t.Run(tc.tName, func(t *testing.T) {
			var out bytes.Buffer

			cmdArgs := []string{
				"openssl", "aes-256-cbc",
				"-pass", fmt.Sprintf("pass:%s", testPassphrase),
				"-md", tc.tMdParam,
				"-in", "/dev/stdin",
			}

			if tc.tPBKDF {
				cmdArgs = append(cmdArgs, "-pbkdf2")
			}

			cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...) //#nosec:G204 -- Hardcoded tests, this is fine
			cmd.Stdout = &out
			cmd.Stdin = strings.NewReader(testPlaintext)

			require.NoError(t, cmd.Run())

			data, err := o.DecryptBinaryBytes(testPassphrase, out.Bytes(), tc.tMdFunc)
			require.NoError(t, err)

			if !assert.Equal(t, testPlaintext, string(data)) {
				t.Logf("Data: %s\nPlaintext: %s", string(data), testPlaintext)
			}
		})
	}
}

func TestDecryptFromString(t *testing.T) {
	o := New()

	for _, tc := range testTable {
		t.Run(tc.tName, func(t *testing.T) {
			var out bytes.Buffer

			cmdArgs := []string{
				"openssl", "aes-256-cbc",
				"-base64",
				"-pass", fmt.Sprintf("pass:%s", testPassphrase),
				"-md", tc.tMdParam,
			}

			if tc.tPBKDF {
				cmdArgs = append(cmdArgs, "-pbkdf2")
			}

			cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...) //#nosec:G204 -- Hardcoded tests, this is fine
			cmd.Stdout = &out
			cmd.Stdin = strings.NewReader(testPlaintext)

			require.NoError(t, cmd.Run())

			data, err := o.DecryptBytes(testPassphrase, out.Bytes(), tc.tMdFunc)
			require.NoError(t, err)

			if !assert.Equal(t, testPlaintext, string(data)) {
				t.Logf("Data: %s\nPlaintext: %s", string(data), testPlaintext)
			}
		})
	}
}

func TestEncryptToDecrypt(t *testing.T) {
	o := New()

	enc, err := o.EncryptBytes(testPassphrase, []byte(testPlaintext), BytesToKeySHA256)
	require.NoError(t, err)

	dec, err := o.DecryptBytes(testPassphrase, enc, BytesToKeySHA256)
	require.NoError(t, err)

	assert.Equal(t, testPlaintext, string(dec))
}

func TestEncryptToDecryptWithCustomSalt(t *testing.T) {
	salt := []byte("saltsalt")

	o := New()

	enc, err := o.EncryptBytesWithSaltAndDigestFunc(testPassphrase, salt, []byte(testPlaintext), BytesToKeySHA256)
	require.NoError(t, err)

	dec, err := o.DecryptBytes(testPassphrase, enc, BytesToKeySHA256)
	require.NoError(t, err)

	assert.Equal(t, testPlaintext, string(dec))
}

func TestEncryptToOpenSSL(t *testing.T) {
	for _, tc := range testTable {
		t.Run(tc.tName, func(t *testing.T) {
			fmt.Printf("testPlaintext = %v\n", testPlaintext)
			fmt.Printf("testPlaintext = %v\n", []byte(testPlaintext))
			o := New()

			salt, err := o.GenerateSalt()
			require.NoError(t, err)

			enc, err := o.EncryptBytesWithSaltAndDigestFunc(testPassphrase, salt, []byte(testPlaintext), tc.tMdFunc)
			require.NoError(t, err)

			enc = append(enc, '\n')

			fmt.Printf("enc = %v\n", enc)
			fmt.Printf("string(enc) = %v\n", string(enc))

			var out bytes.Buffer

			cmdArgs := []string{
				"openssl", "aes-256-cbc",
				"-base64", "-d",
				"-pass", fmt.Sprintf("pass:%s", testPassphrase),
				"-md", tc.tMdParam,
				"-in", "/dev/stdin",
			}

			if tc.tPBKDF {
				cmdArgs = append(cmdArgs, "-pbkdf2")
			}
			fmt.Printf("cmdArgs = %v\n", cmdArgs)

			cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...) //#nosec:G204 -- Hardcoded tests, this is fine
			cmd.Stdout = &out
			cmd.Stdin = bytes.NewReader(enc)

			require.NoError(t, cmd.Run())

			assert.Equal(t, testPlaintext, out.String())
			fmt.Printf("out.String() = %v\n", out.String())
			/*
				testPlaintext = hallowelt
				testPlaintext = [104 97 108 108 111 119 101 108 116]
				enc = [85 50 70 115 100 71 86 107 88 49 47 104 115 49 104 56 109 80 84 65 117 118 81 66 82 101 82 87 56 67 55 52 68 57 112 47 110 116 116 54 66 76 52 61 10]
				string(enc) = U2FsdGVkX1/hs1h8mPTAuvQBReRW8C74D9p/ntt6BL4=

				cmdArgs = [openssl aes-256-cbc -base64 -d -pass pass:z4yH36a6zerhfE5427ZV -md sha256 -in /dev/stdin -pbkdf2]
				out.String() = hallowelt


				testPlaintext = hallowelt
				testPlaintext = [104 97 108 108 111 119 101 108 116]
				enc = [85 50 70 115 100 71 86 107 88 49 57 82 116 78 53 84 56 69 102 84 48 43 74 122 120 110 71 69 54 72 88 56 80 98 82 85 122 76 47 114 48 85 103 61 10]
				string(enc) = U2FsdGVkX19RtN5T8EfT0+JzxnGE6HX8PbRUzL/r0Ug=

				备注，每次前10个数是一样的，数字和ASCLL码表对应

				cmdArgs = [openssl aes-256-cbc -base64 -d -pass pass:z4yH36a6zerhfE5427ZV -md sha256 -in /dev/stdin -pbkdf2]
				out.String() = hallowelt

			*/
		})
	}
}

func TestEncryptWithSaltShouldHaveSameOutput(t *testing.T) {
	plaintext := "outputshouldbesame"
	passphrase := "passphrasesupersecure"
	salt := []byte("saltsalt")

	o := New()

	enc1, err := o.EncryptBytesWithSaltAndDigestFunc(passphrase, salt, []byte(plaintext), BytesToKeySHA256)
	require.NoError(t, err)

	enc2, err := o.EncryptBytesWithSaltAndDigestFunc(passphrase, salt, []byte(plaintext), BytesToKeySHA256)
	require.NoError(t, err)

	assert.Equal(t, enc1, enc2)
}

func TestGenerateSalt(t *testing.T) {
	knownSalts := [][]byte{}

	o := New()

	for i := 0; i < 1000; i++ {
		salt, err := o.GenerateSalt()
		require.NoError(t, err)

		for _, ks := range knownSalts {
			assert.NotEqual(t, ks, salt)
			knownSalts = append(knownSalts, salt)
		}
	}
}

func TestSaltValidation(t *testing.T) {
	var err error
	o := New()

	_, err = o.EncryptBytesWithSaltAndDigestFunc(testPassphrase, []byte("12345"), []byte(testPlaintext), BytesToKeySHA256)
	assert.ErrorIs(t, err, ErrInvalidSalt)

	_, err = o.EncryptBytesWithSaltAndDigestFunc(testPassphrase, []byte("1234567890"), []byte(testPlaintext), BytesToKeySHA256)
	assert.ErrorIs(t, err, ErrInvalidSalt)

	_, err = o.EncryptBytesWithSaltAndDigestFunc(testPassphrase, []byte{0xcb, 0xd5, 0x1a, 0x3, 0x84, 0xba, 0xa8, 0xc8}, []byte(testPlaintext), BytesToKeySHA256)
	assert.NoError(t, err)
}

//
// Benchmarks
//

func benchmarkDecrypt(ciphertext []byte, cg CredsGenerator, b *testing.B) {
	o := New()

	for n := 0; n < b.N; n++ {
		_, err := o.DecryptBytes(testPassphrase, ciphertext, cg)
		require.NoError(b, err)
	}
}

func BenchmarkDecryptMD5(b *testing.B) {
	benchmarkDecrypt([]byte("U2FsdGVkX19ZM5qQJGe/d5A/4pccgH+arBGTp+QnWPU="), BytesToKeyMD5, b)
}

func BenchmarkDecryptSHA1(b *testing.B) {
	benchmarkDecrypt([]byte("U2FsdGVkX1/Yy9kegseq2Ewd4UvjFYCpIEA1cltTA1Q="), BytesToKeySHA1, b)
}

func BenchmarkDecryptSHA256(b *testing.B) {
	benchmarkDecrypt([]byte("U2FsdGVkX1+O68d7BO9ibP8nB5+xtb/27IHlyjJWpl8="), BytesToKeySHA256, b)
}

func benchmarkEncrypt(plaintext string, cg CredsGenerator, b *testing.B) {
	o := New()
	salt, _ := o.GenerateSalt()

	for n := 0; n < b.N; n++ {
		_, err := o.EncryptBytesWithSaltAndDigestFunc(testPassphrase, salt, []byte(plaintext), cg)
		require.NoError(b, err)
	}
}

func BenchmarkEncryptMD5(b *testing.B) {
	benchmarkEncrypt(testPlaintext, BytesToKeyMD5, b)
}

func BenchmarkEncryptSHA1(b *testing.B) {
	benchmarkEncrypt(testPlaintext, BytesToKeySHA1, b)
}

func BenchmarkEncryptSHA256(b *testing.B) {
	benchmarkEncrypt(testPlaintext, BytesToKeySHA256, b)
}

func BenchmarkGenerateSalt(b *testing.B) {
	o := New()
	for n := 0; n < b.N; n++ {
		_, err := o.GenerateSalt()
		require.NoError(b, err)
	}
}
