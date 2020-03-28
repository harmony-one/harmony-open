package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
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
	"time"

	"fmt"
)

type AwsConfiguration struct {
	AccessKey string `json:"aws_access_key_id"`
	SecretKey string `json:"aws_secret_access_key"`
	Region    string `json:"aws_region"`
}

func readline(prompt string, timeout time.Duration) (string, error) {
	s := make(chan string)
	e := make(chan error)

	go func() {
		fmt.Print(prompt)
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil {
			e <- err
		} else {
			s <- line
		}
		close(s)
		close(e)
	}()

	select {
	case line := <-s:
		return line, nil
	case err := <-e:
		return "", err
	case <-time.After(timeout):
		return "", errors.New("Timeout")
	}
}

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

func setupAwsService()  *kms.KMS {
	var envJSON string
	envSettingString, err := readline(envJSON, 1 * time.Second);
	var awsConfig AwsConfiguration

	if (err == nil) {
		err := json.Unmarshal([]byte(envSettingString), &awsConfig)
		if err != nil {
			fmt.Println(envSettingString, " is not a valid JSON string for setting aws configuration.")
			panic(err)
		}
	}

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	svc := kms.New(sess, &aws.Config{
		Region: aws.String(awsConfig.Region),
		Credentials: credentials.NewStaticCredentials(awsConfig.AccessKey, awsConfig.SecretKey, ""),
	})

	return svc
}

func printHeader()  {
	fmt.Println("\nBLS key utility for the Harmony blockchain")
	fmt.Println("Usage:")
	fmt.Println(os.Args[0], "[command]\n")
	fmt.Println("Available Commands:")
	fmt.Println("generate\tgenerate a new BLS key and encrypt it with aws CMK key")
	fmt.Println("convert\t\tconvert the legacy BLS key file to new aws CMK encrypted BLS key file")
	fmt.Println("rotate\t\tdecrypt and re-encrypt BLS key using new aws CMK key ID")
	fmt.Println("pubkey\t\tdisplay the public key of a BLS key file\n")
	fmt.Println("command arguments:")
}

func generateBlsKey(keyId string) {
	svc := setupAwsService()

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

func rotateBlsKey(blsKeyFileOld, blsKeyFileNew, keyId string) {
	svc := setupAwsService()

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

func displayPublicKey(blsKeyFile string) {
	svc := setupAwsService()

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

func convertOldBlsKeyFile(legacyBlsKeyFile, blsPass, newBlsKeyFile, keyId string) {
	svc := setupAwsService()

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
	generateCommand  := flag.NewFlagSet("generate", flag.ExitOnError)
	rotateCommand  := flag.NewFlagSet("rotate", flag.ExitOnError)
	convertCommand := flag.NewFlagSet("convert", flag.ExitOnError)
	pubkeyCommand  := flag.NewFlagSet("pubkey", flag.ExitOnError)

	generateCmdKeyId  := generateCommand.String("enc_key_id", "", "The aws CMK key Id used for encrypting new bls key file. (Required)")

	rotateCmdBlsOld := rotateCommand.String("old_blskey_file", "", "The old aws CMK encrypted bls private key file. (Required)")
	rotateCmdBlsNew := rotateCommand.String("new_blskey_file", "", "The new aws CMK encrypted bls private key file. (Required)")
	rotateCmdKeyId  := rotateCommand.String("new_key_id", "", "The aws CMK key Id used for encrypting new bls key file. (Required)")

	convertCmdBlsOld := convertCommand.String("legacy_blskey_file", "", "The legacy encrypted file of bls serialized private key by passphrase. (Required)")
	convertCmdBlsNew := convertCommand.String("cms_blskey_file", "", "The new aws CMK encrypted bls private key file. (Required)")
	convertCmdBlsPass:= convertCommand.String("blspass", "", "The passphrase to decrypt the encrypted bls file. i.e. file:<file_name>, pass:<string>, env:<key>")
	convertCmdKeyId  := convertCommand.String("key_id", "", "The aws CMK key Id used for encrypting bls key file. (Required)")

	pubkeyCmdBlsKey  := pubkeyCommand.String("blskey_file", "", "The aws CMK encrypted bls private key file . (Required)")

	if len(os.Args) < 2 {
		printHeader()
		fmt.Println("generate:")
		generateCommand.PrintDefaults()
		fmt.Println("convert:")
		convertCommand.PrintDefaults()
		fmt.Println("roate:")
		rotateCommand.PrintDefaults()
		fmt.Println("pubkey:")
		pubkeyCommand.PrintDefaults()
		os.Exit(1)
	}

	//flag.Parse()
	switch os.Args[1] {
	case "generate":
		generateCommand.Parse(os.Args[2:])
	case "rotate":
		rotateCommand.Parse(os.Args[2:])
	case "convert":
		convertCommand.Parse(os.Args[2:])
	case "pubkey":
		pubkeyCommand.Parse(os.Args[2:])
	default:
		printHeader()
		fmt.Println("generate")
		generateCommand.PrintDefaults()
		fmt.Println("convert")
		convertCommand.PrintDefaults()
		fmt.Println("roate")
		rotateCommand.PrintDefaults()
		fmt.Println("pubkey")
		pubkeyCommand.PrintDefaults()
		os.Exit(1)
	}

	if generateCommand.Parsed() {
		// Required Flags
		if *generateCmdKeyId == "" {
			generateCommand.PrintDefaults()
			os.Exit(1)
		}

		generateBlsKey(*generateCmdKeyId)
	}

	if rotateCommand.Parsed() {
		// Required Flags
		if *rotateCmdBlsOld == "" || *rotateCmdBlsNew == "" || *rotateCmdBlsNew == "" {
			rotateCommand.PrintDefaults()
			os.Exit(1)
		}

		rotateBlsKey(*rotateCmdBlsOld, *rotateCmdBlsNew, *rotateCmdKeyId)
	}

	if convertCommand.Parsed() {
		// Required Flags
		if *convertCmdBlsOld == "" || *convertCmdBlsNew == "" || *convertCmdKeyId == "" {
			convertCommand.PrintDefaults()
			os.Exit(1)
		}

		convertOldBlsKeyFile(*convertCmdBlsOld, *convertCmdBlsPass, *convertCmdBlsNew, *convertCmdKeyId)
	}

	if pubkeyCommand.Parsed() {
		// Required Flags
		if *pubkeyCmdBlsKey == "" {
			pubkeyCommand.PrintDefaults()
			os.Exit(1)
		}

		displayPublicKey(*pubkeyCmdBlsKey)
	}
}