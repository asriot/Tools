import sys
import enum
import logging
import subprocess
import argparse
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES

def aes_ECB_Decrypt(data, key, key_size):
    cipher = AES.new(key, AES.MODE_ECB)
    data = unpad(cipher.decrypt(data), key_size)
    return (data)

def decrypt_file(in_file, aes_key , out_file):
    with open(in_file, 'rb') as f:
        in_data = f.read()

    aes_key_bytes = bytes.fromhex(aes_key)
    out_data = aes_ECB_Decrypt(in_data, aes_key_bytes, len(aes_key_bytes))

    with open(out_file, 'wb') as f:
        f.write(out_data)

def main():

    parser = argparse.ArgumentParser(description='Decrypt file with AES ECB')

    parser.add_argument('--input', type=str, required=True,
                        help='The path to the encrypted file')
    parser.add_argument('--output', type=str, required=True,
                        help='The path to the output file')
    parser.add_argument("--aes_key", type=str, required=False,
                        help=('AES key used to encrypt the whole factory files, '
                              'provide 16-byte or 32-byte hex, e.g. "1234567890abcdef1234567890abcdef"'))

    args = parser.parse_args()

    decrypt_file(args.input, args.aes_key, args.output)

if __name__ == "__main__":
    logging.basicConfig(format='[%(asctime)s] [%(levelname)7s] - %(message)s', level=logging.INFO)
    main()