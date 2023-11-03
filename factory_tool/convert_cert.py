#!/usr/bin/env python3
#
#    Copyright (c) 2022 Project CHIP Authors
#    All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#

import sys
import enum
import logging
import subprocess
import argparse
from bitarray import bitarray
from bitarray.util import ba2int
import cryptography.hazmat.backends
import cryptography.x509

# Convert the certificate in PEM format to DER format
def convert_x509_cert_from_pem_to_der(pem_file, out_der_file):
    with open(pem_file, 'rb') as f:
        pem_data = f.read()

    pem_cert = cryptography.x509.load_pem_x509_certificate(pem_data, cryptography.hazmat.backends.default_backend())
    der_cert = pem_cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.DER)

    with open(out_der_file, 'wb') as f:
        f.write(der_cert)

def main():

    parser = argparse.ArgumentParser(description='convert certificate from pem format to der format')

    parser.add_argument('--pem', type=str, required=True,
                        help='The path to the certificate in pem format')
    parser.add_argument('--der', type=str, required=True,
                        help='The path to the certificate in der format')

    args = parser.parse_args()

    convert_x509_cert_from_pem_to_der(args.pem, args.der)

if __name__ == "__main__":
    logging.basicConfig(format='[%(asctime)s] [%(levelname)7s] - %(message)s', level=logging.INFO)
    main()