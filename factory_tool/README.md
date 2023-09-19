# ASR Matter factory tool

This tool is designed to generate factory partitions for mass production.

## Dependencies

Install python dependencies
```
cd path/to/Tools/factory_tool
python3 -m pip install -r requirements.txt
```

## Build Matter App

To build the Matter App with the ASR Factory Data Provider.

If you use the `build_examples.py` script, add argument `-factory`.
For example:
```
./scripts/build/build_examples.py --target asr-$ASR_BOARD-lighting-factory build
```

If you use the `matter_build_example.sh` script, add argument`chip_enable_factory_data=true` and
`chip_use_transitional_commissionable_data_provider=false`
For example:
```
./matter_build_example.sh ./examples/lighting-app/asr out/example_app chip_enable_factory_data=true chip_use_transitional_commissionable_data_provider=false
```

## Usage

`python ASR_matter_factory_tool.py -h` lists all the optional arguments.

The following commands generate factory partitions using the default testing PAI
keys, certificates, and CD in Matter project, Vendor ID: 0xFFF2, Product ID: 0x8001,
Discriminator: 3434, and Passcode: 99663300.
You can make it using yours instead in real production.

```
python ASR_matter_factory_tool.py --discriminator 3434 --passcode 99663300 \
--dac-cert  ../credentials/test/attestation/Chip-Test-DAC-FFF2-8001-0008-Cert.pem \
--dac-key  ../credentials/test/attestation/Chip-Test-DAC-FFF2-8001-0008-Key.pem \
--pai-cert  ../credentials/test/attestation/Chip-Test-PAI-FFF2-8001-Cert.der \
--cd  ../credentials/test/certification-declaration/Chip-Test-CD-FFF2-8001.der \
--vendor-id 0xFFF2 --vendor-name ASR --product-id 0x8001 --product-name asr5821 \
--qrcode
```

The output manufacturing binary file is `ASR_matter_factory.bin`.
The QR image file is `ASR_matter_QRcode.png`.

## Flashing the manufacturing binary

`DOGO` tool is used to flash the manufacturing binary to the board.

For ASR582X, the burning address is `0x101C1000`.

For ASR595X, the burning address is `0x801C1000`.

For ASR550X, the burning address is `0x101EE000`.