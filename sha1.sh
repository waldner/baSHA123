#!/bin/bash

sha1_F(){
  local x=$1 y=$2 z=$3
  ensure_nbits $(( (x & y) | (~x & z) )) 32
}  

sha1_G(){
  local x=$1 y=$2 z=$3
  ensure_nbits $((  x ^ y ^ z )) 32
}

sha1_H(){
  local x=$1 y=$2 z=$3
  ensure_nbits $(( (x & y) | (x & z) | (y & z) )) 32
}

sha1_I(){
  local x=$1 y=$2 z=$3
  ensure_nbits $((  x ^ y ^ z )) 32
}

# rotates left with wraparound
left_rotate(){
  local n=$1 s=$2 nbits=$3
  ensure_nbits $(( (n << s) | (n >> ($nbits - s)) )) "$nbits"
}

ensure_nbits(){
  local n=$1 nbits=$2
  SHA1_RESULT=$(( $n & (2 ** $nbits - 1) ))
}



sha1_init(){

  local -a temp
  local elem

  temp=()
  for elem in "${SHA1_WORDS_INITX[@]}"; do
    temp+=( $((16#$elem)) )
  done

  SHA1_WORDS=()
  for i in {0..4}; do
    bytes_to_int_msb "${temp[@]:$i*4:4}"
    SHA1_WORDS[$i]=$SHA1_RESULT
  done
}


read_chunk(){

  local data length status
  
  local fd=$1
  
  BYTES_READ=0
  CHUNK=()
  
  local to_read=64   # 512 bits
  
  while true; do 
    IFS= read -u $fd -d '' -r -n $to_read data
    status=$?

    length=${#data}
    #echo "Read ${length} BYTES_READ"

    for ((i=0; i < length; i++)); do
      printf -v "CHUNK[BYTES_READ+i]" "%d" "'${data:i:1}"
    done

    # if we read less than we wanted, and it's not EOF, it means we also have
    # a delimiter
    if [ $length -lt $to_read ] && [ $status -eq 0 ]; then
      CHUNK[BYTES_READ+length]=0
      ((length++))
    fi

    ((BYTES_READ+=length))
    if [ $BYTES_READ -ge 64 ]; then
      break
    fi
    if [ $status -ne 0 ]; then
      break
    fi
    ((to_read-=length))
  done

}

# turns the input bytes into a number (MSB first argument)
bytes_to_int_msb(){

  local i=0 n
  local result=0

  for (( a=$#; a > 0; a-- )); do
    n=${!a}
    ((result+=($n << ($i * 8) ) ))
    ((i++))
  done

  SHA1_RESULT=$result
}

# given an integer, convert it to 4 bytes (big endian)
int_to_bytes_be(){

  local n=$1

  SHA1_RESULT=$(( (n >> 24) & 16#ff ))
  SHA1_RESULT="${SHA1_RESULT} $(( (n >> 16) & 16#ff ))"
  SHA1_RESULT="${SHA1_RESULT} $(( (n >> 8) & 16#ff ))"
  SHA1_RESULT="${SHA1_RESULT} $(( n & 16#ff ))"
}



process_chunk(){

  local -a x

  for ((count=0; count < 16; count++)); do
    bytes_to_int_msb "${CHUNK[@]:$count*4:4}"
    x[count]=$SHA1_RESULT
  done

  # extend with 64 extra words
  for ((count = 16; count < 80; count++)); do
    left_rotate $(( x[count - 3] ^ x[count - 8] ^ x[count - 14] ^ x[count - 16])) 1 32
    x[count]=$SHA1_RESULT
  done

  local a=${SHA1_WORDS[0]}
  local b=${SHA1_WORDS[1]}
  local c=${SHA1_WORDS[2]}
  local d=${SHA1_WORDS[3]}
  local e=${SHA1_WORDS[4]}


  for ((round = 0; round < 80; round++)); do
    if [ $round -lt 20 ]; then
      sha1_func=F
      k=$((16#5A827999))
    elif [ $round -lt 40 ]; then
      sha1_func=G
      k=$((16#6ED9EBA1))
    elif [ $round -lt 60 ]; then
      sha1_func=H 
      k=$((16#8F1BBCDC))
    else
      sha1_func=I
      k=$((16#CA62C1D6))
    fi

    sha1_${sha1_func} $b $c $d 
    result=$SHA1_RESULT

    left_rotate $a 5 32

    ensure_nbits $(( SHA1_RESULT + result + e + k + x[round] )) 32
    temp=$SHA1_RESULT
    e=$d
    d=$c
    left_rotate $b 30 32
    c=$SHA1_RESULT
    b=$a
    a=$temp

  done

  ensure_nbits $(( SHA1_WORDS[0] + $a )) 32
  SHA1_WORDS[0]=$SHA1_RESULT

  ensure_nbits $(( SHA1_WORDS[1] + $b )) 32
  SHA1_WORDS[1]=$SHA1_RESULT

  ensure_nbits $(( SHA1_WORDS[2] + $c )) 32
  SHA1_WORDS[2]=$SHA1_RESULT

  ensure_nbits $(( SHA1_WORDS[3] + $d )) 32
  SHA1_WORDS[3]=$SHA1_RESULT

  ensure_nbits $(( SHA1_WORDS[4] + $e )) 32
  SHA1_WORDS[4]=$SHA1_RESULT
}


### BEGIN HERE

export LC_ALL=C

declare -a SHA1_WORDS_INITX

SHA1_WORDS_INITX=( 67 45 23 01
                   ef cd ab 89
                   98 ba dc fe
                   10 32 54 76
                   c3 d2 e1 f0 )

declare -a SHA1_WORDS

sha1_init

BYTES_READ=0
tot_bytes=0
declare -a CHUNK

fd=0

while true; do
  read_chunk $fd

  ((tot_bytes+=BYTES_READ))

  if [ $BYTES_READ -lt 64 ]; then
    # EOF, add padding

    # find next multiple of 512 bits (64 bytes), taking into account the last 8 bytes are for length
    length_with_padding=$(( tot_bytes + 9 + 64 - 1 - ( (tot_bytes + 9 - 1) % 64 ) ))

    # how many bytes of padding (without length)
    padding_len=$(( length_with_padding - 8 - tot_bytes ))

    #echo "tot_bytes: $tot_bytes, length with padding: $length_with_padding, padding_len: $padding_len"

    declare -a padding

    padding[0]=$(( 16#80 ))

    for (( byte = 1; byte < padding_len; byte++ )); do
      padding[byte]=0
    done

    # add length of the original message, in bits, encoded as 8 bytes, each word big-endian
    #length=$(( tot_bytes * 8 ))

    ls4=$(( (tot_bytes * 8) & 16#ffffffff ))
    ms4=$(( ( (tot_bytes * 8) >> 32 ) & 16#ffffffff ))

    int_to_bytes_be ${ms4}
    declare -a temp=( $SHA1_RESULT )
    padding[padding_len]=${temp[0]}
    padding[padding_len+1]=${temp[1]}
    padding[padding_len+2]=${temp[2]}
    padding[padding_len+3]=${temp[3]}

    int_to_bytes_be ${ls4}
    declare -a temp=( $SHA1_RESULT )
    padding[padding_len+4]=${temp[0]}
    padding[padding_len+5]=${temp[1]}
    padding[padding_len+6]=${temp[2]}
    padding[padding_len+7]=${temp[3]}


    # now add padding to chunk, process as needed (1 or 2 times)
 
    padding_count=0
    while true; do

      #echo "bytes is $bytes"

      CHUNK[$BYTES_READ]=${padding[$padding_count]}
      ((padding_count++))
      ((BYTES_READ++))

      if [ $BYTES_READ -ge 64 ]; then
        process_chunk
        CHUNK=()
        BYTES_READ=0
      fi

      if [ $padding_count -ge $(( padding_len + 8 )) ]; then
        break 2
      fi

    done


  else
    process_chunk
  fi
done

result=

for ((i=0; i < 5; i++)); do
  int_to_bytes_be ${SHA1_WORDS[i]}
  declare -a temp=( $SHA1_RESULT )
  printf -v t '%02x' "${temp[@]}"
  printf -v result '%s%s' "${result}" "${t}"
done

echo "$result"

