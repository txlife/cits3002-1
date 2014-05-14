#!/bin/bash
if [[ $# -ne 1 ]]; then
  echo 'Usage: pem_to_der.sh pem_file_name'
  exit
fi
openssl x509 -in $1.pem -outform der -out $1.crt
