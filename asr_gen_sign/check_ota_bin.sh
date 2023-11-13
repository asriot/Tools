#!/usr/bin/env bash

file_name=$1
ota_file_name=$file_name
ota_file_name=${ota_file_name}_ota
echo "file:$file_name"
filesize1=$(stat --format=%s "$file_name.bin")
echo "burning file size:$filesize1"
filesize2=$(stat --format=%s "$ota_file_name.bin")
echo "ota file size:$filesize2"
offset=$(expr $filesize1 - 4)
echo "ota region size offset:$offset"
maxsize=$(od -An -td4 -j $offset -N 4 $file_name.bin|sed "s/ //g")
echo "ota max size:$maxsize"
if [ $filesize2 -lt $maxsize ]
then
    echo "ota file size check ok"
else
    echo "========================================================================="
    echo "ota file size has exceeded the ota partition, please decrease your code !"
    echo "========================================================================="
    rm $ota_file_name.bin
fi
