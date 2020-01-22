#!/bin/bash
openssl dgst -sha256 -verify harmony_pubkey.pem -signature harmony.sig harmony
