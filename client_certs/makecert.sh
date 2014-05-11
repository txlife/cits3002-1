#!/bin/bash
if [[ $# -ne 3 ]]; then
	echo "Usage: ./self_sign_cert.sh private_key_file output_cert_file"
	exit 
fi
openssl req -new -key $1 -out certreq.csr
openssl x509 -req -days 3650 -in certreq.csr -signkey $1 -out $2
