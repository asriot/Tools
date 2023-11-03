import sys
import enum
import logging
import subprocess
import argparse
from Crypto.Cipher import AES

def unpad(s):
    while(1):
        if(s[-1:] == b'\x00'):
            s = s[:-1]
        else:
            break
    return s

def aes_ECB_Decrypt(data , aes_key):
    cipher = AES.new(key=bytes.fromhex(aes_key), mode=AES.MODE_ECB)
    result = cipher.decrypt(data)
    return unpad(result)

def decrypt_file(in_file, aes_key , out_file):
    with open(in_file, 'rb') as f:
        in_data = f.read()

    out_data = aes_ECB_Decrypt(in_data, aes_key)

    with open(out_file, 'wb') as f:
        f.write(out_data)

def main():

    parser = argparse.ArgumentParser(description='Decrypt file with AES ECB')

    parser.add_argument('--input', type=str, required=True,
                        help='The path to the encrypted file')
    parser.add_argument('--output', type=str, required=True,
                        help='The path to the output file')
    parser.add_argument("--aes128_key", type=str, required=True,
                        help=('AES 128-bit key used to encrypt the whole factory files, '
                              'provide 32-byte hex string, e.g. "1234567890abcdef1234567890abcdef"'))

    args = parser.parse_args()

    decrypt_file(args.input, args.aes128_key, args.output)

if __name__ == "__main__":
    logging.basicConfig(format='[%(asctime)s] [%(levelname)7s] - %(message)s', level=logging.INFO)
    main()