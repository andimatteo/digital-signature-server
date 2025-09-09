echo "verify signature on prova.txt: "
openssl dgst -sha256 -verify data/server/keys/prova_pubkey.pem -signature data/client/prova.txt.sig data/client/prova.txt
