#!/usr/bin/env bash

MATTER_PATH=/workspace/connectedhomeip

TARGET_IMAGE=$MATTER_PATH/out/asr-asr582x-lighting/chip-asr-lighting-example.bin

BOOTLOADER_PATH=$MATTER_PATH/third_party/asr/asr582x/asr_sdk/tools/factory_bin/ASR582X/ASRBOOTLOADER-58XX-MX-V2.1.1-4M-UART1-SECUREBOOT-202311021647.bin

SIGN_TOOL=../gen_sign

IMAGE_GEN_HEADER_TOOL=$MATTER_PATH/third_party/asr/asr582x/asr_sdk/tools/otaImage/image_gen_header

CERT_DIR=.

SIGN_ALG_TYPE=rsa

$SIGN_TOOL --sign_$SIGN_ALG_TYPE='--cert='"$CERT_DIR"' --base=0x10000000 --image='"$BOOTLOADER_PATH"''
mv  ${BOOTLOADER_PATH%\.bin}.$SIGN_ALG_TYPE.signed.bin .

$SIGN_TOOL --sign_$SIGN_ALG_TYPE='--cert='"$CERT_DIR"' --base=0x10012000 --image='"$TARGET_IMAGE"''
TARGET_IMAGE_SIGNED=${TARGET_IMAGE%\.bin}.$SIGN_ALG_TYPE.signed

$IMAGE_GEN_HEADER_TOOL $TARGET_IMAGE_SIGNED.bin -d COMBO -b REMAPPING -r

sh ../check_ota_bin.sh $TARGET_IMAGE_SIGNED

mv  ${TARGET_IMAGE_SIGNED}.bin .
mv  ${TARGET_IMAGE_SIGNED}_ota.bin .
