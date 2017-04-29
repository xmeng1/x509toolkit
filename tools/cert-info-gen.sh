#!/usr/bin/env bash
# get the full file name for the $1 the first parameter after the command
fullFile=$1
# get the file name and extension name
filename=$(basename "$fullFile")
extension="${filename##*.}"
filename="${filename%.*}"
echo ${extension}
echo ${filename}#
# open the case insensitive
shopt -s nocasematch
# if pem format
if [ "${extension}" == "pem" ] ; then
    openssl x509 -in $1 -text -noout >> ${filename}.pem.txt
# if der format
elif [ "${extension}" == "der" ] ; then
    openssl x509 -in $1 -inform der -text -noout >> ${filename}.der.txt
else
    echo "just support the perm and der, if the file is Based64, just change the file extension to pem, or change it to der"
fi

