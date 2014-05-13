#!/bin/bash
for i in `seq 1 10`; do
	openssl req -new -newkey rsa:1024 -days 365 -nodes -x509 -keyout $i\_key.pem -out $i\_crt.pem
done
