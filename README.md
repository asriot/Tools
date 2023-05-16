# Tools

## scripts

### matter_build_example.sh
build scripit for matter, for example:

setup ASR IC:
```
export ASR_IC=asr582x
```
setup ASR toolchain:
```
export ASR_TOOLCHAIN_PATH=/home/ubuntu/compiler/gcc-arm-none-eabi-9-2019-q4-major/bin/
```
build lighting-app:
```
./matter_build_example.sh ./examples/lighting-app/asr out/example_app
```

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
