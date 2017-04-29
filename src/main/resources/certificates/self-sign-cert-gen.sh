#!/usr/bin/env bash

openssl req -newkey rsa:2048 -new -nodes -keyout key.pem -x509 -days 3650 -out ds-cloud-ca-cert.pem

#Country Name (2 letter code) [XX]:UK
#State or Province Name (full name) []:Milton Keynes
#Locality Name (eg, city) [Default City]:Milton Keynes
#Organization Name (eg, company) [Default Company Ltd]:xmeng1
#Organizational Unit Name (eg, section) []:x509toolkit
#Common Name (eg, your name or your server's hostname) []:io.github.xmeng1.x509
#Email Address []:x.meng@outlook.com

openssl pkcs8 -topk8 -inform PEM -outform DER -in key.pem  -nocrypt > pkcs8_key

openssl x509 -in  ds-cloud-ca-cert.pem -text -noout >> ds-cloud-ca-cert.txt