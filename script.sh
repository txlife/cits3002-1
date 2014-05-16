#!/bin/bash

for i in `seq 1 1000`; do
	./client -h localhost:3490 -v server_code.c Aole
done
