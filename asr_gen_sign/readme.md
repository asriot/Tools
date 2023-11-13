# gen_sign 使用说明 #

## ECDSA加签使用说明 ##
### 示例：gen_sign.exe --sign_ecdsa='--curve=secp256r1 --cert=<cert_dir_path> --image=<image_file_path> --base=FLASH_BASE_ADDR'
1. --sign_ecdsa (不可缺省)，表示采用ecdsa算法对image文件进行加签。
2. --curve (不可缺省，参数：secp256r1, secp256k1)，设置ecdsa加签算法所用的椭圆曲线类型。
3. --cert (不可缺省)，传入ecdsa私钥存储目录。工具会在该目录下查找是否有ecdsa子目录，且子目录下是否存在ecc私钥及对应公钥的hash文件。如不存在则会自动创建相应目录或文件。(注：用户需注意备份保存该私钥文件，如丢失会导致已加签芯片后续将无法继续ota)
4. --image (不可缺省)，传入待加签文件的文件路径。
5. --base (不可缺省)，设置当前加签固件运行芯片的flash基址，alto及bass芯片为：0x80000000。

## RSA加签使用说明 ##
### 示例：gen_sign.exe --sign_rsa='--cert=<cert_dir_path> --image=<image_file_path> --base=FLASH_BASE_ADDR'
1. --sign_rsa (不可缺省)，表示采用RSA算法对image文件进行加签。
2. --cert (不可缺省)，传入rsa私钥存储目录。工具会在该目录下查找是否有rsa子目录，且子目录下是否存在rsa两份私钥、两份私钥文件对应的密码文件、priv_key_1对应公钥的hash文件。如不存在则会自动创建相应目录或文件。(注：用户需注意备份保存该私钥文件，如丢失会导致已加签芯片后续将无法继续ota)
3. --image (不可缺省)，传入待加签文件的文件路径。
4. --base (不可缺省)，设置当前加签固件运行芯片的flash基址，alto及bass芯片为：0x80000000。
