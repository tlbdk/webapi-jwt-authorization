# webapi-jwt-authorization
Sample project that shows how to do JWT validation and map claims to roles for OWIN WebAPI 2

## jwt.io key conversion

Get the private keys from jwt.io under "ALGORITHM: RS256".

1. Convert private key to a format openssl will work with

Openssl needs a PEM key that has base64 lines brakes: 

``` bash
# copy/paste the stuff between the start and end marker and press ctr-d
echo "-----BEGIN RSA PRIVATE KEY-----" > jwt.io.key
cat | openssl base64 -d -A | openssl base64 >> jwt.io.key
echo "-----END RSA PRIVATE KEY-----" >> jwt.io.key
```

2. Create signing request

``` bash
openssl req -sha256 -new -key jwt.io.key -out jwt.io.csr -subj '/CN=localhost'
```

3. Create selfsigned certificate

``` bash
openssl x509 -req -sha256 -days 3650 -in jwt.io.csr -signkey jwt.io.key -out jwt.io.crt
```

4. Export certificate in pfx format with private key

*Note on macOS you might be having a very old version of openssl in path so use the one from brew: /usr/local/opt/openssl/bin/openssl*

``` bash
usr/local/opt/openssl/bin/openssl pkcs12 -export -keysig -CSP "Microsoft Enhanced RSA and AES Cryptographic Provider" -in jwt.io.crt -inkey jwt.io.key -out jwt.io.pfx -passout pass:qwerty1234
```
