#!/usr/bin/bash
openssl ecparam -genkey -name prime256v1 -noout -out private.pem
openssl ec -in private.pem -pubout -out public.pem
openssl pkcs8 -topk8 -nocrypt -in private.pem -out private_new.pem
rm private.pem
mv private_new.pem private.pem
