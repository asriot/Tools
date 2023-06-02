# Tools

## toolchain

### toolchain for ASR596X
```
cd toolchain
```
```
cat asr_riscv_gnu_toolchain_10.2_ubuntu-16.04.tar.bz2.part* > asr_riscv_gnu_toolchain_10.2_ubuntu-16.04.tar.bz2
```
```
mkdir -p asr_riscv_gnu_toolchain_10.2_ubuntu-16.04
```
```
tar -jxvf asr_riscv_gnu_toolchain_10.2_ubuntu-16.04.tar.bz2 -C asr_riscv_gnu_toolchain_10.2_ubuntu-16.04/
```
then export `ASR_TOOLCHAIN_PATH`:
```
export ASR_TOOLCHAIN_PATH={abs-path-to-toolchain}/asr_riscv_gnu_toolchain_10.2_ubuntu-16.04/bin/
```

### toolchain for ASR582X
```
wget https://developer.arm.com/-/media/Files/downloads/gnu-rm/9-2019q4/RC2.1/gcc-arm-none-eabi-9-2019-q4-major-x86_64-linux.tar.bz2
```
```
tar -jxvf gcc-arm-none-eabi-9-2019-q4-major-x86_64-linux.tar.bz2
```
then export `ASR_TOOLCHAIN_PATH`:
```
export ASR_TOOLCHAIN_PATH={abs-path-to-toolchain}/gcc-arm-none-eabi-9-2019-q4-major/bin/
```

## scripts

### matter_build_example.sh
build scripit for matter, first put this file to `connectedhomeip` directory, then setup ASR BOARD:
```
export ASR_BOARD=asr582x
```
please make sure `ASR_TOOLCHAIN_PATH` is alreay export, then build lighting-app:
```
./matter_build_example.sh ./examples/lighting-app/asr out/example_app
```

## factory tool

[matter factory tool](factory_tool/README.md) is designed to generate factory partitions for mass production.

## factory bin

 - bootloader
 - ate