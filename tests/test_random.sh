#!/bin/bash

# get a random amount of random bytes, then calculate hash

round=0
round_max=50

rfile=/tmp/random_file

while [ $round -lt $round_max ]; do

  printf "Round: $round, "

  len=$(( ($RANDOM % 5000) + 1 )) 
  echo "len: $len"

  dd if=/dev/urandom status=none bs=1 count=$RANDOM > "$rfile"

  for hash in md5 sha1 sha224 sha256 sha384 sha512 sha512-224 sha512-256; do 
    printf "Doing hash: ${hash}..."
    our_value=$(./${hash}.sh < "$rfile")
    openssl_value=$(openssl $hash < "$rfile" | awk '{print $2}')
    if [ "$our_value" = "$openssl_value" ]; then
      result="Ok"
    else
      result="Fail"
    fi
    echo "$result"
  done
  ((round++))
done

rm -rf "$rfile"
