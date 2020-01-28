import argparse

import boto3
import hashlib
import binascii
from aws_encryption_sdk.exceptions import UnknownRegionError


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


def sign_harmony_file(inputFile, sigFile, signingAlgorithm, keyId):
    region_name = region_from_key_id(keyId)
    kms_client = boto3.client('kms', region_name=region_name)

    with open(inputFile, "rb") as f:
        data = f.read()
        digest = hashlib.sha256(data).digest()

        print("File Name   : ", inputFile)
        print("Digest      : ", binascii.hexlify(digest))
        print("Sign Key ID : ", keyId)
        print("Algorithm   : ", signingAlgorithm)
        print("Signature   : ", sigFile)

        response = kms_client.sign(
            KeyId=keyId,
            Message=digest,
            MessageType='DIGEST',
            SigningAlgorithm=signingAlgorithm
        )

        signature = response['Signature']

    if signature:
        with open(sigFile, "wb") as of:
            of.write(signature)


def parse_args():
    parser = argparse.ArgumentParser(description='Sign binaries for harmony')
    parser.add_argument('input_filepath', type=str, help="The binary file to be signed.")
    parser.add_argument('output_sig_filepath', type=str, help="The output of the signature")
    parser.add_argument('--sig_alg', type=str, help="The signing algorithm",
                        default="RSASSA_PKCS1_V1_5_SHA_256")
    parser.add_argument('--aws_key_id', type=str, help="The ARN signing key id.",
                        default="arn:aws:kms:us-west-2:656503231766:key/370d45bb-d629-45d7-8d1c-db0560895690")
    parser.add_argument('--aws_profile_name', type=str, help="The AWS profile with credentials",
                        default="harmony-kms")
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    boto3.setup_default_session(profile_name=args.aws_profile_name)
    print("AWS profile : ", args.aws_profile_name)
    sign_harmony_file(args.input_filepath, args.output_sig_filepath, args.sig_alg, args.aws_key_id)
