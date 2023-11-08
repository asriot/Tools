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
from asyncio.constants import LOG_THRESHOLD_FOR_CONNLOST_WRITES
import os
import sys
import shutil
import logging
import argparse
import subprocess
import cryptography.hazmat.backends
import cryptography.x509
from types import SimpleNamespace
from enum import Enum
from hashlib import sha256
import csv
import base64
import hashlib
import struct
import qrcode
import platform
from ecdsa.curves import NIST256p
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES

THIS_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(THIS_DIR, 'setup_payload'))
from generate_setup_payload import CommissioningFlow, SetupPayload

INVALID_PASSCODES = [00000000, 11111111, 22222222, 33333333, 44444444, 55555555,
                     66666666, 77777777, 88888888, 99999999, 12345678, 87654321]

ASR_PARTITION_CSV = 'ASR_matter_partition.csv'
ASR_FACTORY_CSV = 'ASR_csv_table.csv'
ASR_FACTORY_BIN = 'ASR_matter_factory.bin'
ASR_FACTORY_QR = 'ASR_matter_QRcode.png'
ASR_FACTORY_QR_TXT = 'ASR_matter_QRcode.txt'
ASR_DAC_CERT = 'ASR_matter_dacCert.bin'
ASR_DAC_PRIKEY = 'ASR_matter_privkey.bin'
ASR_DAC_PUBKEY = 'ASR_matter_pubkey.bin'

int2hexInstrFormat = lambda x: (hex(int(x)).split('0x')[1])
lenEvenorOdd = lambda x: (len(x)%2)
int2bytes = lambda x: int2hexInstrFormat(x).zfill(len(int2hexInstrFormat(x)) + lenEvenorOdd(int2hexInstrFormat(x)))

FACTORY_DATA = {
    # CommissionableDataProvider
    'version':{
        'type': 'data',
        'encoding': 'u32',
        'value': None,
    },
    'config':{
        'type': 'data',
        'encoding': 'u32',
        'value': None,
    },
    'iteration-count':{
        'type': 'data',
        'encoding': 'u32',
        'value': None,
    },
    'salt':{
        'type': 'data',
        'encoding': 'string',
        'value': None,
    },
    'verifier':{
        'type': 'data',
        'encoding': 'string',
        'value': None,
    },
    'discriminator':{
        'type': 'data',
        'encoding': 'u32',
        'value': None,
    },
    # CommissionableDataProvider
    'dac-cert':{
        'type': 'file',
        'encoding': 'binary',
        'value': None,
    },
    'dac-pri-key':{
        'type': 'file',
        'encoding': 'binary',
        'value': None,
    },
    'dac-pub-key':{
        'type': 'file',
        'encoding': 'binary',
        'value': None,
    },
    'pai-cert':{
        'type': 'file',
        'encoding': 'binary',
        'value': None,
    },
    'cert-dclrn': {
        'type': 'file',
        'encoding': 'binary',
        'value': None,
    },
    # DeviceInstanceInforProvider
    'vendor-name': {
        'type': 'data',
        'encoding': 'string',
        'value': None,
    },
    'vendor-id': {
        'type': 'data',
        'encoding': 'u32',
        'value': None,
    },
    'product-name': {
        'type': 'data',
        'encoding': 'string',
        'value': None,
    },
    'product-id': {
        'type': 'data',
        'encoding': 'u32',
        'value': None,
    },
    'mfg-date': {
        'type': 'data',
        'encoding': 'string',
        'value': None,
    },
    'serial-num': {
        'type': 'data',
        'encoding': 'string',
        'value': None,
    },
    'hardware-ver': {
        'type': 'data',
        'encoding': 'u32',
        'value': None,
    },
    'hw-ver-str': {
        'type': 'data',
        'encoding': 'string',
        'value': None,
    },
    'rd-id-uid': {
        'type': 'data',
        'encoding': 'string',
        'value': None,
    },
    'product-url': {
        'type': 'data',
        'encoding': 'string',
        'value': None,
    },
    'product-label': {
        'type': 'data',
        'encoding': 'string',
        'value': None,
    },
    'part-number': {
        'type': 'data',
        'encoding': 'string',
        'value': None,
    },
    'chip-id': {
        'type': 'data',
        'encoding': 'string',
        'value': None,
    },
}

def check_str_range(s, min_len, max_len, name):
    if s and ((len(s) < min_len) or (len(s) > max_len)):
        logging.error('%s must be between %d and %d characters', name, min_len, max_len)
        sys.exit(1)

def check_int_range(value, min_value, max_value, name):
    if value and ((value < min_value) or (value > max_value)):
        logging.error('%s is out of range, should be in range [%d, %d]', name, min_value, max_value)
        sys.exit(1)

def validate_args(args):
    # Validate the passcode
    if args.passcode is not None:
        if ((args.passcode < 0x0000001 and args.passcode > 0x5F5E0FE) or (args.passcode in INVALID_PASSCODES)):
            logging.error('Invalid passcode:' + str(args.passcode))
            sys.exit(1)

    check_int_range(args.discriminator, 0x0000, 0x0FFF, 'Discriminator')
    check_int_range(args.product_id, 0x0000, 0xFFFF, 'Product id')
    check_int_range(args.vendor_id, 0x0000, 0xFFFF, 'Vendor id')
    check_str_range(args.vendor_name, 1, 32, 'Vendor name')
    check_str_range(args.product_name, 1, 32, 'Product name')
    check_str_range(args.rd_id_uid, 32, 32, 'Rotating device Unique id')
    check_int_range(args.iteration_count, 1000, 10000, 'iteration count')
    check_int_range(args.salt_len, 16, 32, 'salt len')
    check_str_range(args.mfg_date, 10, 10, 'Manufacture date')
    check_str_range(args.serial_num, 1, 32, 'Serial number')
    check_int_range(args.hw_ver, 0x0000, 0xFFFF, 'Hardware version')
    check_str_range(args.hw_ver_str, 1, 32, 'Hardware version string')
    check_str_range(args.product_url, 1, 256, 'Product URL')
    check_str_range(args.product_label, 1, 64, 'Product Label')
    check_str_range(args.part_number, 1, 32, 'Part Number')

    if not os.path.isdir(args.out):
        os.makedirs(args.out, exist_ok=True)

    #logging.info('Discriminator:{} Passcode:{}'.format(args.discriminator, args.passcode))

##################### QR Code #####################
def generate_onboarding_data(args):
    setup_payload = SetupPayload(discriminator=args.discriminator,
                                    pincode=args.passcode,
                                    rendezvous=args.discovery_mode,
                                    flow=args.commissioning_flow,
                                    vid=args.vendor_id,
                                    pid=args.product_id)

    logging.info('Generated QR code: ' + setup_payload.generate_qrcode())
    logging.info('Generated manual code: ' + setup_payload.generate_manualcode())
    with open(os.path.join(args.out, ASR_FACTORY_QR_TXT), "w") as manual_code_file:
        manual_code_file.write("Manualcode : " + setup_payload.generate_manualcode() + "\n")
        manual_code_file.write("QRCode : " + setup_payload.generate_qrcode())
    qr = qrcode.make(setup_payload.generate_qrcode())
    qr.save(os.path.join(args.out, ASR_FACTORY_QR))

##################### Spake2p #####################
# Length of `w0s` and `w1s` elements
WS_LENGTH = NIST256p.baselen + 8

def generate_verifier(passcode: int, salt: bytes, iterations: int) -> bytes:
    ws = hashlib.pbkdf2_hmac('sha256', struct.pack('<I', passcode), salt, iterations, WS_LENGTH * 2)
    w0 = int.from_bytes(ws[:WS_LENGTH], byteorder='big') % NIST256p.order
    w1 = int.from_bytes(ws[WS_LENGTH:], byteorder='big') % NIST256p.order
    L = NIST256p.generator * w1

    return w0.to_bytes(NIST256p.baselen, byteorder='big') + L.to_bytes('uncompressed')

def generate_spake2_salt(args):
    return os.urandom(args.salt_len)

def gen_spake2p_params(args):
    salt = generate_spake2_salt(args)
    verifier = generate_verifier(args.passcode, salt, args.iteration_count)

    return {
        'Iteration Count': args.iteration_count,
        'Salt': base64.b64encode(salt).decode('utf-8'),
        'Verifier': base64.b64encode(verifier).decode('utf-8'),
    }

def str2hexInlist(data:str)-> list:

    if len(data) % 2 != 0:
        logging.error('input data illegal')
        sys.exit(1)

    hex_list = []

    for i in range(len(data)//2):
        temp_data = data[2*i:2*i+2]
        hex_list.append(int(temp_data,16))
    hex_list.reverse()
    return hex_list[:]

def populate_factory_data(args, spake2p_params):
    FACTORY_DATA['discriminator']['value'] = args.discriminator

    if spake2p_params:
        FACTORY_DATA['iteration-count']['value'] = spake2p_params['Iteration Count']
        FACTORY_DATA['salt']['value'] = spake2p_params['Salt']
        FACTORY_DATA['verifier']['value'] = spake2p_params['Verifier']

    # get data from file
    FACTORY_DATA['dac-cert']['value'] = os.path.abspath(os.path.join(args.out, ASR_DAC_CERT))
    FACTORY_DATA['pai-cert']['value'] = os.path.abspath(args.pai_cert)
    FACTORY_DATA['cert-dclrn']['value'] = os.path.abspath(args.cd)
    FACTORY_DATA['dac-pri-key']['value'] = os.path.abspath(os.path.join(args.out, ASR_DAC_PRIKEY))
    FACTORY_DATA['dac-pub-key']['value'] = os.path.abspath(os.path.join(args.out, ASR_DAC_PUBKEY))

    # output interation-count, salt, verifier to the terminal
    #logging.info("iteration-count : %s", FACTORY_DATA['iteration-count']['value'])
    #logging.info("salt            : %s", FACTORY_DATA['salt']['value'])
    #logging.info("verifier        : %s", FACTORY_DATA['verifier']['value'])

    if args.vendor_id is not None:
        FACTORY_DATA['vendor-id']['value'] = args.vendor_id
    if args.vendor_name is not None:
        FACTORY_DATA['vendor-name']['value'] = args.vendor_name
    if args.product_id is not None:
        FACTORY_DATA['product-id']['value'] = args.product_id
    if args.product_name is not None:
        FACTORY_DATA['product-name']['value'] = args.product_name
    if args.rd_id_uid is not None:
        FACTORY_DATA['rd-id-uid']['value'] = args.rd_id_uid
    if args.chip_id is not None:
        FACTORY_DATA['chip-id']['value'] = args.chip_id
    if args.mfg_date is not None:
        FACTORY_DATA['mfg-date']['value'] = args.mfg_date
    if args.serial_num is not None:
        FACTORY_DATA['serial-num']['value'] = args.serial_num
    if args.hw_ver is not None:
        FACTORY_DATA['hardware-ver']['value'] = args.hw_ver
    if args.hw_ver_str is not None:
        FACTORY_DATA['hw-ver-str']['value'] = args.hw_ver_str
    if args.product_url is not None:
        FACTORY_DATA['product-url']['value'] = args.product_url
    if args.product_label is not None:
        FACTORY_DATA['product-label']['value'] = args.product_label
    if args.part_number is not None:
        FACTORY_DATA['part-number']['value'] = args.part_number

    FACTORY_DATA['version']['value'] = args.version
    # config, bit 1: nokey
    matter_config_value = 0x133f0000
    if args.nokey:
        FACTORY_DATA['config']['value'] = matter_config_value | 0x01
    else:
        FACTORY_DATA['config']['value'] = matter_config_value

# Convert the certificate in PEM format to DER format
def convert_x509_cert_from_pem_to_der(pem_file, out_der_file):
    with open(pem_file, 'rb') as f:
        pem_data = f.read()

    pem_cert = cryptography.x509.load_pem_x509_certificate(pem_data, cryptography.hazmat.backends.default_backend())
    der_cert = pem_cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.DER)

    with open(out_der_file, 'wb') as f:
        f.write(der_cert)

# Generate the Public and Private key pair binaries
def generate_keypair_bin(pem_file, out_privkey_bin, out_pubkey_bin):
    with open(pem_file, 'rb') as f:
        pem_data = f.read()

    key_pem = cryptography.hazmat.primitives.serialization.load_pem_private_key(pem_data, None)
    private_number_val = key_pem.private_numbers().private_value
    public_number_x = key_pem.public_key().public_numbers().x
    public_number_y = key_pem.public_key().public_numbers().y
    public_key_first_byte = 0x04

    with open(out_privkey_bin, 'wb') as f:
        f.write(private_number_val.to_bytes(32, byteorder='big'))

    with open(out_pubkey_bin, 'wb') as f:
        f.write(public_key_first_byte.to_bytes(1, byteorder='big'))
        f.write(public_number_x.to_bytes(32, byteorder='big'))
        f.write(public_number_y.to_bytes(32, byteorder='big'))

def generate_matter_csv(args):

    out_csv_filename = os.path.join(args.out, ASR_PARTITION_CSV)
    csv_content = 'key,type,encoding,value\n'

    for k, v in FACTORY_DATA.items():
        if v['value'] is None:
            continue
        if k == 'dac-pri-key' and args.nokey:
            continue
        csv_content += f"{k},{v['type']},{v['encoding']},{v['value']}\n"

    with open(out_csv_filename, 'w') as f:
        f.write(csv_content)

    logging.info('Generated the factory partition csv file : {}'.format(os.path.abspath(out_csv_filename)))

def aes_ECB_Encrypt(data, key, key_size):
    cipher = AES.new(key, AES.MODE_ECB)
    data = cipher.encrypt(pad(data, key_size))
    return (data)

def encrypt_file(in_file, aes_key , out_file):
    with open(in_file, 'rb') as f:
        in_data = f.read()
    aes_key_bytes = bytes.fromhex(aes_key)
    out_data = aes_ECB_Encrypt(in_data, aes_key_bytes, len(aes_key_bytes))

    with open(out_file, 'wb') as f:
        f.write(out_data)

def generate_factory_bin(args):

    in_csv_filename = os.path.join(args.out, ASR_PARTITION_CSV)

    global ASR_FACTORY_BIN
    if args.nokey:
       ASR_FACTORY_BIN = ASR_FACTORY_BIN[:-len(".bin")] + "_nokey.bin"

    if platform.system() == 'Windows':
        gen_partition_tool= 'gen_partition.exe'
    else:
        gen_partition_tool= './gen_partition'

    aes_key_size = 16
    if (args.aes_key is None):
        FILE_NAME = os.path.join(args.out, ASR_FACTORY_BIN)
        cmd = [
            gen_partition_tool,
            '--asr_matter',
            '--csv',
            in_csv_filename,
            '--out',
            FILE_NAME,
        ]
    else:
        ASR_FACTORY_BIN = ASR_FACTORY_BIN[:-len(".bin")] + "_encrypt.bin"
        FILE_NAME_ENCRYPT = os.path.join(args.out, ASR_FACTORY_BIN)
        aes_key_bytes = bytes.fromhex(args.aes_key)

        if len(aes_key_bytes) == 16 :
            aes_key_mode = "--aes128_key"
        elif len(aes_key_bytes) == 32:
            aes_key_mode = "--aes256_key"
        else:
            logging.error('aes key length %d is invalid', len(aes_key_bytes))
            sys.exit(1)

        cmd = [
            gen_partition_tool,
            '--asr_matter',
            '--csv',
            in_csv_filename,
            '--out',
            FILE_NAME_ENCRYPT,
            aes_key_mode,
            args.aes_key,
        ]

    subprocess.run(cmd)

    if (args.aes_key is None):
        logging.info('Generated the factory partition bin file : {}'.format(os.path.abspath(FILE_NAME)))
    else:
        if args.nokey:
            PRI_KEY_ENCRYPT = FACTORY_DATA['dac-pri-key']['value'][:-len(".bin")] + "_encrypt.bin"
            encrypt_file(FACTORY_DATA['dac-pri-key']['value'], args.aes_key, PRI_KEY_ENCRYPT)
            os.remove(FACTORY_DATA['dac-pri-key']['value'])
            FACTORY_DATA['dac-pri-key']['value'] = PRI_KEY_ENCRYPT
        logging.info('Generated the encrypted factory partition bin file : {}'.format(os.path.abspath(FILE_NAME_ENCRYPT)))

def clean_up(args):
    os.remove(FACTORY_DATA['dac-cert']['value'])
    os.remove(FACTORY_DATA['dac-pub-key']['value'])
    if not args.nokey:
        os.remove(FACTORY_DATA['dac-pri-key']['value'])

def generate_csv_log(args):
    global ASR_FACTORY_BIN
    FILE_NAME = os.path.join(args.out, ASR_FACTORY_BIN)
    CSV_FILE_NAME = os.path.join(args.out , '../', ASR_FACTORY_CSV)

    if args.qrcode:
        setup_payload = SetupPayload(discriminator=args.discriminator,
                                        pincode=args.passcode,
                                        rendezvous=args.discovery_mode,
                                        flow=args.commissioning_flow,
                                        vid=args.vendor_id,
                                        pid=args.product_id)
        chip_qrcode = setup_payload.generate_qrcode()
        qr_file_path = os.path.join(args.out, ASR_FACTORY_QR)
    else:
        chip_qrcode = 'none'
        qr_file_path = 'none'

    if not os.path.exists(CSV_FILE_NAME):
        csv_header = ["ID","Batch","VendorID","VendorName","productID","productName","Version",\
                    "CommissioningFlow","RendezVousInformation","Discriminator","SetupPINCode",\
                    "iteration_count","salt_len","mfg_date" "serial_num","hw_ver","hw_ver_str",\
                    "product_url","product_label","part_number",\
                    "factory_file1","factory_file2","QR_file","QR_code"]
        with open(CSV_FILE_NAME, 'w',newline='\n') as file_handler:
            csv_handler = csv.writer(file_handler)
            csv_handler.writerow(csv_header)

    if not args.nokey:
        FACTORY_DATA['dac-pri-key']['value'] = 'none'

    csv_content = [args.chip_id,args.batch,hex(args.vendor_id)[2:],args.vendor_name,hex(args.product_id)[2:],\
                args.product_name, args.version,args.commissioning_flow,args.discovery_mode,\
                args.discriminator,args.passcode, args.iteration_count,args.salt_len,args.mfg_date,\
                args.serial_num,args.hw_ver,args.hw_ver_str,args.product_url,args.product_label,args.part_number,\
                os.path.abspath(FILE_NAME),FACTORY_DATA['dac-pri-key']['value'],\
                os.path.abspath(qr_file_path) ,chip_qrcode]

    with open(CSV_FILE_NAME, 'a', newline='\n') as file_handler:
        csv_handler = csv.writer(file_handler)
        csv_handler.writerow(csv_content)

def main():
    def any_base_int(s): return int(s, 0)

    parser = argparse.ArgumentParser(description='ASR Factory binary generator tool V2')

    # These will be used by CommissionalbeDataProvider
    parser.add_argument('-p', '--passcode', type=any_base_int, required=True,
                        help='The setup passcode for pairing, range: 0x01-0x5F5E0FE')
    parser.add_argument('-d', '--discriminator', type=any_base_int, required=True,
                        help='The discriminator for pairing, range: 0x00-0x0FFF')

    # These will be used by DeviceAttestationCredentialsProvider
    parser.add_argument('--dac-cert', type=str, required=True,
                        help='The path to the DAC certificate in pem format')
    parser.add_argument('--dac-key', type=str, required=True,
                        help='The path to the DAC private key in pem format')
    parser.add_argument('--pai-cert', type=str, required=True,
                        help='The path to the PAI certificate in der format')
    parser.add_argument('--cd', type=str, required=True,
                        help='The path to the certificate declaration der format')

    parser.add_argument('--iteration_count', type=int, required=False, default=10000,
                        help="iteration_count's valid range is in [1000,10000]")
    parser.add_argument('--salt_len', type=int, required=False, default=32,
                        help="salt_len's valid range is in [16,32]")

    # These will be used by DeviceInstanceInfoProvider
    parser.add_argument('--vendor-id', type=any_base_int, required=False, default=0x133f, help='Vendor id')
    parser.add_argument('--vendor-name', type=str, required=False, default="ASR", help='Vendor name')
    parser.add_argument('--product-id', type=any_base_int, required=False, default=0x5821, help='Product id')
    parser.add_argument('--product-name', type=str, required=False, default="asr582x", help='Product name')
    parser.add_argument('--mfg-date', type=str, required=False, default="2023-07-10", help='Manufacturing date in format YYYY-MM-DD')
    parser.add_argument('--serial-num', type=str, required=False, default="sn1234", help='Serial number')
    parser.add_argument('--hw-ver', type=any_base_int, required=False, default=0x100, help='Hardware version')
    parser.add_argument('--hw-ver-str', type=str, required=False, default="hwASR5821", help='Hardware version string')
    parser.add_argument('--product-url', type=str, required=False, default="http://www.asrmicro.com/en/goods/proinfo/36.html", help='Product URL')
    parser.add_argument('--product-label', type=str, required=False, default="ASR582X is a highly integrated combo SoC", help='Product Label')
    parser.add_argument('--part-number', type=str, required=False, default="abc", help='Part Number')

    parser.add_argument("--rd-id-uid", type=str, required=False, default="1234567890abcdef1234567890abcdef",
                        help=('128-bit unique identifier for generating rotating device identifier, '
                              'provide 32-byte hex string, e.g. "1234567890abcdef1234567890abcdef"'))

    parser.add_argument('--discovery-mode', type=any_base_int, default=2,
                                 help='Commissionable device discovery netowrking technology. \
                                          1:WiFi-SoftAP, 2:BLE, 4:On-network. Default is BLE.', choices=[1, 2, 4])
    parser.add_argument('--commissioning-flow', type=any_base_int, default=0,
                                 help='Device commissioning flow, 0:Standard, 1:User-Intent, 2:Custom. \
                                          Default is 0.', choices=[0, 1, 2])
    parser.add_argument('--version', type=str, required=False, default='2', help='version infomation')
    parser.add_argument('--chip-id', type=str, required=False, default="0000", help='Chip id')
    parser.add_argument('--batch', type=str, required=False, default="0000", help='Batch')
    parser.add_argument('--nokey', action='store_true', required=False,
                        help='No DAC private key in the factory.bin')

    parser.add_argument('--qrcode', action='store_true', required=False,
                        help=("Generate a Manual Code and QR Code according to provided factory data set."
                              "As a result a PNG image containing QRCode and a .txt file containing Manual Code will be available within output directory"))

    parser.add_argument('--csv_log', action='store_true', required=False,
                        help='option to Generate CSV table')

    parser.add_argument('--out', type=str, required=False, default="./out",
                        help='Output folder for factory files')

    parser.add_argument("--aes_key", type=str, required=False,
                        help=('AES key used to encrypt the whole factory files, '
                              'provide 16-byte or 32-byte hex, e.g. "1234567890abcdef1234567890abcdef"'))

    args = parser.parse_args()
    validate_args(args)
    spake2p_params = gen_spake2p_params(args)
    populate_factory_data(args, spake2p_params)
    convert_x509_cert_from_pem_to_der(args.dac_cert, FACTORY_DATA['dac-cert']['value'])
    generate_keypair_bin(args.dac_key, FACTORY_DATA['dac-pri-key']['value'], FACTORY_DATA['dac-pub-key']['value'])

    generate_matter_csv(args)

    generate_factory_bin(args)

    if args.qrcode:
        generate_onboarding_data(args)

    clean_up(args)

    if args.csv_log:
        generate_csv_log(args)

if __name__ == "__main__":
    logging.basicConfig(format='[%(asctime)s] [%(levelname)7s] - %(message)s', level=logging.INFO)
    main()