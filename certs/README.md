# How to (re)generate the X.509 certificates?

```sh
mkcert -install
cp $(mkcert -CAROOT)/rootCA.pem .

mkcert example.org
# Note: Use "changeit" as password.
openssl pkcs12 -export -out example.org.p12 -inkey example.org-key.pem -in example.org.pem
rm example.org-key.pem example.org.pem
```
