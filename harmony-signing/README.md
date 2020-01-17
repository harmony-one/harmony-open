# Harmony Signing Tool

  Harmony releases various excutables (i.e. harmony block chain node code, command line tools etc)  regularly through harmony S3 buckets and open to public. 
  For better safety, all the released binaries shall be signed by harmony siging key (a RSA 4096 asymmetric key). 
  The private siging key is maintained by amazon aws KMS(Key Management Service) and the key is not visible by anyone from Harmony.

  Only designated aws users (assigned by harmony aws administrator) with signing permission can use the private key to sign binary. 
  The public key of harmony signing key is open to public and anyone can use it to verify the authencity of the binary.


##  Setup the tools

### Install virtualenv
```bash
[sudo] pip install -U setuptools
[sudo] pip install virtualenv
```

### Install required packages in virtualenv
```bash
python3 -m virtualenv v
source venv/bin/activate
pip install -r requirement.txt
deactivate
```

## Sign binary before releasing binary (requires AWS account and harmony signing key permission)

  Now you can use the python script sign_binary.py to sign the executable. 
  Please note that this script has to be invoked inside the virtual environment (source venv/bin/activate).
  As the script requires the Harmony signing key, please login to your aws account before signing.
 
  python signing_binary.py [binary_file] [signature_file]
  An example signing session is shown below, where harmony is the executable and harmony.sig is the output signature.

```bash
source venv/bin/activate
python sign_binary.py harmony harmony.sig
```

## Verify the signature on client side

  Both harmony binary and signature file can be downloaded publically on harmony S3 buckets. Once downloaded, the authenticity of harmony binary should be verified.
  The verification can be done by using the open source tool openssl and the harmony public key harmony_pubkey.pem..

```bash
openssl dgst -sha256 -verify harmony_pubkey.pem -signature harmony.sig harmony
Verified OK
```
  The expected output from openssl should be "Verified OK".
