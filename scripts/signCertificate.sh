#!/bin/bash
if [[ $# -ne 3 ]]; then
  echo "Usage: signCertificate.sh CA_num CA_key_num client_csr_num"
  exit
fi

touch index.txt
rm index.txt
touch index.txt
#openssl ca -batch -config openssl.conf -in $3_csr.pem  -cert $1_crt.pem -keyfile $2_key.pem -out ./signed/$3_crt.pem
openssl x509 -req -in $3_csr.pem -md5 -CA $1_crt.pem -CAkey $2_key.pem -CAcreateserial -out ./signed/$3_crt.pem
