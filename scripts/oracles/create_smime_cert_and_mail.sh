#! /bin/bash
#
# create_smime_cert_and_mail.sh
# Copyright (C) 2023 Fabian Ising
#
# Distributed under terms of the MIT license.
#

if [ ! -f smime_key.pem ]; then
    echo "Generating smime cert"
    mkcert -cert-file=smime_crt.pem -key-file=smime_key.pem oracle@example.org
fi

if [ ! -f smime.p12 ]; then
    echo "Creating p12 file..."
    openssl pkcs12 -legacy -export -in smime_crt.pem -inkey smime_key.pem -out smime.p12 -name "oracle@example.org" -passout pass:changeit
fi

if [ $# -eq 0 ]; then
    echo "Usage: $0 plaintext_file"
    exit 1
fi
if [ -f $1 ]; then
    BASENAME=${1%.*}
    echo "Encrypting $1 to ${BASENAME}_smime.eml"
    openssl smime -encrypt -aes-128-cbc -out ${BASENAME}_smime.eml -recip -in smime_crt.pem < $1
    # Our script only expects the base64, so we remove the header (first 5 lines) and the empty line at
    # the end
    sed '1,5d;$d' ${BASENAME}_smime.eml > ${BASENAME}.sm
    echo "Output only base64 to ${BASENAME}.sm"
else
    echo "$1 does not exist!"
fi
