import aws_encryption_sdk
import boto3
import sys
import hashlib
import binascii

#key ID for harmony signing key, created by aws, using aws KMS 
harmonySigningKeyId = "arn:aws:kms:us-west-2:656503231766:key/370d45bb-d629-45d7-8d1c-db0560895690"
signingAlgorithm    = "RSASSA_PKCS1_V1_5_SHA_256"

def region_from_key_id(signingKeyId, default_region=None):
    try:
        region_name = signingKeyId.split(":", 4)[3]
    except IndexError:
        if default_region is None:
            raise UnknownRegionError(
                "No default region found and no region determinable from key id: {}".format(signingKeyId)
            )
        region_name = default_region
    return region_name


def sign_harmony_file(inputFile, sigFile, keyId = harmonySigningKeyId):
    region_name = region_from_key_id(keyId)
    kms_client = boto3.client('kms', region_name)

    signature = ''
    with open(inputFile, "rb") as f:
        data = f.read()
        digest = hashlib.sha256(data).digest()

        print("File Name   : ", inputFile)
        print("Digest      : ", binascii.hexlify(digest))
        print("Sign Key ID : ", harmonySigningKeyId)
        print("Algorithm   : ", signingAlgorithm)
        print("Signature   : ", sigFile)

        response = kms_client.sign(
            KeyId = keyId,
            Message = digest,
            MessageType = 'DIGEST',
            SigningAlgorithm=signingAlgorithm
        )

        signature = response['Signature']

    if signature != '':
        with open(sigFile,"wb") as of:
            of.write(signature)

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: python3 sign_harmony_file [aws_key_id] [input_file] [output_signature]")
    else:
        sign_harmony_file(sys.argv[2], sys.argv[3], sys.argv[1])
