#!/bin/bash
for i in `seq 1 10`;do
  openssl req -config openssl.conf -batch -new -key $i\_key.pem -out $i\_csr.pem
done
