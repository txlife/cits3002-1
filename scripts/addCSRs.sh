for i in `seq 1 10`; do
	openssl req -new -nodes -keyout $i.pem -out $i.csr -days 365
done