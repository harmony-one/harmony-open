package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"github.com/harmony-one/harmony/crypto/bls"
	ffi_bls "github.com/harmony-one/bls/ffi/go/bls"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"fmt"
)

func writeToFile(filename string, data string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.WriteString(file, data)
	if err != nil {
		return err
	}
	return file.Sync()
}

func readAllAsString(r io.Reader) (data string, err error) {
	bytes, err := ioutil.ReadAll(r)
	return string(bytes), err
}

func getPassphraseFromSource(src string) (pass string, err error) {
	switch src {
	case "stdin":
		return readAllAsString(os.Stdin)
	}
	methodArg := strings.SplitN(src, ":", 2)
	if len(methodArg) < 2 {
		return "", errors.Errorf("invalid passphrase reading method %#v", src)
	}
	method := methodArg[0]
	arg := methodArg[1]
	switch method {
	case "pass":
		return arg, nil
	case "env":
		pass, ok := os.LookupEnv(arg)
		if !ok {
			return "", errors.Errorf("environment variable %#v undefined", arg)
		}
		return pass, nil
	case "file":
		f, err := os.Open(arg)
		if err != nil {
			return "", errors.Wrapf(err, "cannot open file %#v", arg)
		}
		defer func() { _ = f.Close() }()
		return readAllAsString(f)
	case "fd":
		fd, err := strconv.ParseUint(arg, 10, 0)
		if err != nil {
			return "", errors.Wrapf(err, "invalid fd literal %#v", arg)
		}
		f := os.NewFile(uintptr(fd), "(passphrase-source)")
		if f == nil {
			return "", errors.Errorf("cannot open fd %#v", fd)
		}
		defer func() { _ = f.Close() }()
		return readAllAsString(f)
	}
	return "", errors.Errorf("invalid passphrase reading method %#v", method)
}

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func decryptRaw(data []byte, passphrase string) ([]byte, error) {
	var err error
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	return plaintext, err
}

func decrypt(encrypted []byte, passphrase string) (decrypted []byte, err error) {
	unhexed := make([]byte, hex.DecodedLen(len(encrypted)))
	if _, err = hex.Decode(unhexed, encrypted); err == nil {
		if decrypted, err = decryptRaw(unhexed, passphrase); err == nil {
			return decrypted, nil
		}
	}
	// At this point err != nil, either from hex decode or from decryptRaw.
	decrypted, binErr := decryptRaw(encrypted, passphrase)
	if binErr != nil {
		// Disregard binary decryption error and return the original error,
		// because our canonical form is hex and not binary.
		return nil, err
	}
	return decrypted, nil
}

// LoadBlsKeyWithPassPhrase loads bls key with passphrase.
func loadBlsKeyWithPassPhrase(fileName, passphrase string) (*ffi_bls.SecretKey, error) {
	encryptedPrivateKeyBytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	for len(passphrase) > 0 && passphrase[len(passphrase)-1] == '\n' {
		passphrase = passphrase[:len(passphrase)-1]
	}
	decryptedBytes, err := decrypt(encryptedPrivateKeyBytes, passphrase)
	if err != nil {
		return nil, err
	}

	priKey := &ffi_bls.SecretKey{}
	priKey.DeserializeHexStr(string(decryptedBytes))
	return priKey, nil
}

func setupAwsService(awsAccessKeyId, awsSecretAccessKey, awsRegion string)  *kms.KMS {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	var svc *kms.KMS
	if (awsAccessKeyId != "" && awsSecretAccessKey != "" && awsRegion != "") {
		svc = kms.New(sess, &aws.Config{
		Region: aws.String(awsRegion),
		Credentials: credentials.NewStaticCredentials(awsAccessKeyId, awsSecretAccessKey, "")})
	}  else {
		fmt.Println("No explicit aws key is specified, using aws-region & secret key from aws shared credentials file.")
		svc = kms.New(sess, &aws.Config{})
	}

	return svc
}

func printHeader()  {
	fmt.Println("\nBLS key utility for the Harmony blockchain")
	fmt.Println("Usage:")
	fmt.Println(os.Args[0], "[command][options]\n")
	fmt.Println("Available Commands:")
	fmt.Println("generate\tgenerate a new BLS key and encrypt it with aws CMK key")
	fmt.Println("        \trequired options: key-id\n")
	fmt.Println("convert\t\tconvert the legacy BLS key file to new aws CMK encrypted BLS key file")
	fmt.Println("        \trequired options: key-id blskey-file blspass\n")
	fmt.Println("rotate\t\tdecrypt and re-encrypt BLS key using new aws CMK key ID")
	fmt.Println("        \trequired options: key-id blskey-file new-blskey-file\n")
	fmt.Println("pubkey\t\tdisplay the public key of a BLS key file")
	fmt.Println("        \trequired options: blskey-file\n")
	fmt.Println("command arguments:")
}

func generateBlsKey(svc *kms.KMS, keyId string) {
	if (keyId == "") {
		fmt.Println("parameter key-id is required ")
		os.Exit(1)
	}

	privateKey := bls.RandPrivateKey()
	publicKey := privateKey.GetPublicKey()
	publicKeyHex := publicKey.SerializeToHexStr()

	// Encrypt the data
	result, err := svc.Encrypt(&kms.EncryptInput{
		KeyId: aws.String(keyId),
		Plaintext: privateKey.Serialize(),
	})

	if err != nil {
		fmt.Println("Got error encrypting data: ", err)
		os.Exit(1)
	}

	var filePath string
	if filePath == "" {
		cwd, _ := os.Getwd()
		filePath = fmt.Sprintf("%s/%s.bls", cwd, publicKeyHex)
	}
	err = writeToFile(filePath, hex.EncodeToString(result.CiphertextBlob))
	if err != nil {
		fmt.Println("Error creating the new bls file : %s ", err)
		os.Exit(1)
	} else {
		fmt.Println("Successfully created a new bls key file ", filePath, " using key id ", keyId)
	}
}

func rotateBlsKey(svc *kms.KMS, blsKeyFileOld, blsKeyFileNew, keyId string) {
	if (keyId == "" || blsKeyFileOld == "" || blsKeyFileNew == "") {
		fmt.Println("parameter key-id, blskey-file, new-blskey-file are required ")
		os.Exit(1)
	}

	encryptedPrivateKeyBytes, err := ioutil.ReadFile(blsKeyFileOld)
	if err != nil {
		fmt.Println("Got error %s reading file %s ", err, blsKeyFileOld)
		os.Exit(1)
	}

	unhexed := make([]byte, hex.DecodedLen(len(encryptedPrivateKeyBytes)))
	_, err = hex.Decode(unhexed, encryptedPrivateKeyBytes)
	if err != nil {
		fmt.Println("Got error decoding BLS key data: ", err)
		os.Exit(1)
	}

	reEncrypted, err := svc.ReEncrypt(&kms.ReEncryptInput{CiphertextBlob: unhexed, DestinationKeyId: &keyId})
	if err != nil {
		fmt.Println("Got error re-encrypting data: ", err)
		os.Exit(1)
	}

	err = writeToFile(blsKeyFileNew, hex.EncodeToString(reEncrypted.CiphertextBlob))
	if err != nil {
		fmt.Println("Error creating the new bls file : %s ", err)
		os.Exit(1)
	} else {
		fmt.Println("Successfully created a new bls key file ", blsKeyFileNew, " using key id ", keyId)
	}
}

func displayPublicKey(svc *kms.KMS, blsKeyFile string) {
	if (blsKeyFile == "" ) {
		fmt.Println("parameter blskey-file is required ")
		os.Exit(1)
	}

	encryptedPrivateKeyBytes, err := ioutil.ReadFile(blsKeyFile)
	if err != nil {
		fmt.Println("Got error %s reading file %s ", err, blsKeyFile)
		os.Exit(1)
	}

	unhexed := make([]byte, hex.DecodedLen(len(encryptedPrivateKeyBytes)))
	_, err = hex.Decode(unhexed, encryptedPrivateKeyBytes)
	if err != nil {
		fmt.Println("Got error decoding BLS key data: ", err)
		os.Exit(1)
	}

	clearKey, err := svc.Decrypt(&kms.DecryptInput{
		CiphertextBlob: unhexed,
	})

	if err != nil {
		fmt.Println("Got error re-encrypting data: ", err)
		os.Exit(1)
	}

	priKey := &ffi_bls.SecretKey{}
	priKey.DeserializeHexStr(hex.EncodeToString(clearKey.Plaintext))

	fmt.Println("\nThe BLS public key from file", blsKeyFile, "is ")
	fmt.Println(hex.EncodeToString(priKey.GetPublicKey().Serialize()))
}

func convertOldBlsKeyFile(svc *kms.KMS, legacyBlsKeyFile, blsPass, newBlsKeyFile, keyId string) {
	if (keyId == "" || legacyBlsKeyFile == "" || blsPass == "") {
		fmt.Println("parameter key-id, blskey-file, blspass are required ")
		os.Exit(1)
	}

	var privateKey *ffi_bls.SecretKey
	if legacyBlsKeyFile != "" {
		if blsPass == "" {
			fmt.Println("Needs blspass to decrypt blskey")
			os.Exit(101)
		}
		passphrase, err := getPassphraseFromSource(blsPass)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "ERROR when reading passphrase file: %v\n", err)
			os.Exit(100)
		}
		privateKey, err = loadBlsKeyWithPassPhrase(legacyBlsKeyFile, passphrase)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"failed to load legacy bls key file %s, error = %s\n",
				legacyBlsKeyFile, err)
			os.Exit(100)
		}
	}

	result, err := svc.Encrypt(&kms.EncryptInput{
		KeyId: aws.String(keyId),
		Plaintext: privateKey.Serialize(),
	})

	if err != nil {
		fmt.Println("Got error encrypting data: ", err)
		os.Exit(1)
	}

	err = writeToFile(newBlsKeyFile, hex.EncodeToString(result.CiphertextBlob))
	if err != nil {
		fmt.Println("Error creating the new bls file : %s ", err)
		os.Exit(1)
 	} else {
		fmt.Println("Successfully created a new bls key file ", newBlsKeyFile, " using key id ", keyId)
	}
}

func main() {
	awsAccessKeyId      := flag.String("aws-access-key-id", "", "The aws access key Id.")
	awsSecretAccessKey  := flag.String("aws-secret-access-key", "", "The aws secret access key.")
	awsRegion           := flag.String("aws-region", "", "The aws region.")
	keyId               := flag.String("key-id", "", "The aws CMK key Id used for encrypting bls key file.")
	new_blskey_file     := flag.String("new-blskey-file", "", "The generated bls key file after key rotation.")
	blskey_file     	:= flag.String("blskey-file", "", "The input bls key file.")
	blspass             := flag.String("blspass", "", "The passphrase to decrypt the bls key file. i.e. file:<file_name>, pass:<string>, env:<key>")

	if len(os.Args) < 2 {
		printHeader()
		flag.PrintDefaults()
		os.Exit(1)
	}

	cmd := os.Args[1]
	os.Args = os.Args[1:]
	flag.Parse()

	svc := setupAwsService(*awsAccessKeyId, *awsSecretAccessKey, *awsRegion)

	switch cmd {
		case "generate":
			generateBlsKey(svc, *keyId)
		case "rotate":
			rotateBlsKey(svc, *blskey_file, *new_blskey_file, *keyId)
		case "convert":
			convertOldBlsKeyFile(svc, *blskey_file, *blspass, *new_blskey_file, *keyId)
		case "pubkey":
			displayPublicKey(svc, *blskey_file)
		default:
			printHeader()
			os.Exit(1)
	}
}