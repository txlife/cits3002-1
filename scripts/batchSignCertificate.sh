#!/bin/bash
if [[ $# -ne 1 ]]; then
  echo "Usage: signCertificate.sh sign_list_csv_file"
  exit
fi

while IFS=, read CA ss_cert
do
  first_ca=$CA
  touch index.txt
  rm index.txt
  touch index.txt
  openssl ca -batch -config openssl.conf -ss_cert $ss_cert\_crt.pem  -cert $CA\_crt.pem -keyfile $CA\_key.pem -out ./signed/$ss_cert\_crt.pem
done < $1
