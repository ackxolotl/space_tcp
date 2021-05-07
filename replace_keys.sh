#!/bin/sh
#
# Replace the keys for HMAC and AES and the AES-IV in the S3TP endpoint.

get_bytes() {
    tr -dc 'A-F0-9' < /dev/random | head -c32 | sed 's/.\{2\}/0x&, /g' | cut -c -94
}

BASEDIR=$(dirname $0)
FILE="$BASEDIR/include/space_tcp/endpoint.hpp"

sed -i -E "s/(hmac_key\[16\]\{)[^\}]+/\1$(get_bytes)/" $FILE
sed -i -E "s/(aes_key\[16\]\{)[^\}]+/\1$(get_bytes)/" $FILE
sed -i -E "s/(aes_iv\[16\]\{)[^\}]+/\1$(get_bytes)/" $FILE
