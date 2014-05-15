#!/bin/bash
if [[ $# -ne 1 ]]; then
  echo "Usage: signCertificate.sh sign_list_csv_file"
  exit
fi

while IFS=, read CA ss_cert
do
  ./client -h localhost:3490 -v $ss_cert\_crt.pem $CA
done < $1
