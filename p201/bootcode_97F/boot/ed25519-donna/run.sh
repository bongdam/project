#!/bin/sh

echo "compile gen sig"
gcc test.c ed25519.c -DED25519_TEST -DED25519_REFHASH -o gen_sig

