#!/bin/bash

md5_F(){
  local x=$1 y=$2 z=$3
  ensure_nbits $(( (x & y) | (~x & z) )) 32
}

md5_G(){
  local x=$1 y=$2 z=$3
  ensure_nbits $((  (x & z) | (y & ~z) )) 32
}

md5_H(){
  local x=$1 y=$2 z=$3
  ensure_nbits $(( x ^ y ^ z )) 32
}

md5_I(){
  local x=$1 y=$2 z=$3
  ensure_nbits $(( y ^ (x | ~z) )) 32
}

# rotates left with wraparound
left_rotate(){
  local n=$1 s=$2 nbits=$3

  if [ $s -gt $nbits ]; then
    echo "Error: shift cannot be greater than nbits" >&2
    return
  fi

  ensure_nbits $(( (n << s) | (n >> (nbits - s)) )) "$nbits"
}

ensure_nbits(){
  local n=$1 nbits=$2
  MD5_RESULT=$(( n & (2 ** nbits - 1) ))
}



md5_init(){

  local -a temp
  local elem

  temp=()
  for elem in "${MD5_WORDS_INITX[@]}"; do
    temp+=( $((16#$elem)) )
  done

  MD5_WORDS=()
  bytes_to_int_lsb "${temp[@]:0:4}"
  MD5_WORDS[0]=$MD5_RESULT

  bytes_to_int_lsb "${temp[@]:4:4}"
  MD5_WORDS[1]=$MD5_RESULT

  bytes_to_int_lsb "${temp[@]:8:4}"
  MD5_WORDS[2]=$MD5_RESULT

  bytes_to_int_lsb "${temp[@]:12:4}"
  MD5_WORDS[3]=$MD5_RESULT

  # init K array
  K=()

  for elem in "${KX[@]}"; do
    K+=( $(( 16#$elem )) )
  done
}


read_chunk(){

  local data
  
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

# turns the input bytes into a number (LSB first argument)
bytes_to_int_lsb(){

  local i=0 n
  local result=0

  for n in "$@"; do
    #result=$(( result + ($n << ($i * 8)) ))
    ((result+=(n << (i * 8)) ))
    ((i++))
  done

  MD5_RESULT=$result
}

# given an integer, convert it to 4 bytes (little endian)
int_to_bytes_le(){

  local n=$1

  MD5_RESULT=$(( n & 16#ff ))
  MD5_RESULT="${MD5_RESULT} $(( (n >> 8) & 16#ff ))"
  MD5_RESULT="${MD5_RESULT} $(( (n >> 16) & 16#ff ))"
  MD5_RESULT="${MD5_RESULT} $(( (n >> 24) & 16#ff ))"
}


process_chunk(){

  local a=${MD5_WORDS[0]}
  local b=${MD5_WORDS[1]}
  local c=${MD5_WORDS[2]}
  local d=${MD5_WORDS[3]}

  local -a x    # input, converted to little-endian words

  for ((count=0; count < 16; count++)); do
    bytes_to_int_lsb "${CHUNK[@]:$count*4:4}"
    x[count]=$MD5_RESULT
  done

  for ((round = 0; round < 64; round++)); do
    if [ $round -lt 16 ]; then
      md5_func=F
      nword=$round
    elif [ $round -lt 32 ]; then
      md5_func=G
      nword=$(( (5 * round + 1) % 16 ))
    elif [ $round -lt 48 ]; then
      md5_func=H
      nword=$(( (3 * round + 5) % 16 ))
    else
      md5_func=I
      nword=$(( (7 * round) % 16 ))
    fi

    md5_${md5_func} $b $c $d
    result=$MD5_RESULT

    ensure_nbits $(( result + a + K[round] + x[nword] )) 32
    result=$MD5_RESULT
    a=$d
    d=$c
    c=$b
    
    left_rotate $result ${SHIFTS[$round]} 32

    result=$MD5_RESULT
    ensure_nbits $(( b + result )) 32
    b=$MD5_RESULT

  done

  ensure_nbits $(( MD5_WORDS[0] + a )) 32
  MD5_WORDS[0]=$MD5_RESULT

  ensure_nbits $(( MD5_WORDS[1] + b )) 32
  MD5_WORDS[1]=$MD5_RESULT

  ensure_nbits $(( MD5_WORDS[2] + c )) 32
  MD5_WORDS[2]=$MD5_RESULT

  ensure_nbits $(( MD5_WORDS[3] + d )) 32
  MD5_WORDS[3]=$MD5_RESULT

}


### BEGIN HERE

export LC_ALL=C


declare -a SHIFTS

SHIFTS=( 7 12 17 22  7 12 17 22  7 12 17 22  7 12 17 22
         5  9 14 20  5  9 14 20  5  9 14 20  5  9 14 20
         4 11 16 23  4 11 16 23  4 11 16 23  4 11 16 23
         6 10 15 21  6 10 15 21  6 10 15 21  6 10 15 21 )

declare -a KX K

KX=( d76aa478 e8c7b756 242070db c1bdceee 
     f57c0faf 4787c62a a8304613 fd469501
     698098d8 8b44f7af ffff5bb1 895cd7be
     6b901122 fd987193 a679438e 49b40821
     f61e2562 c040b340 265e5a51 e9b6c7aa
     d62f105d 02441453 d8a1e681 e7d3fbc8
     21e1cde6 c33707d6 f4d50d87 455a14ed
     a9e3e905 fcefa3f8 676f02d9 8d2a4c8a
     fffa3942 8771f681 6d9d6122 fde5380c
     a4beea44 4bdecfa9 f6bb4b60 bebfbc70
     289b7ec6 eaa127fa d4ef3085 04881d05
     d9d4d039 e6db99e5 1fa27cf8 c4ac5665
     f4292244 432aff97 ab9423a7 fc93a039
     655b59c3 8f0ccc92 ffeff47d 85845dd1
     6fa87e4f fe2ce6e0 a3014314 4e0811a1
     f7537e82 bd3af235 2ad7d2bb eb86d391 )

declare -a MD5_WORDS_INITX

MD5_WORDS_INITX=( 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10 )

declare -a MD5_WORDS

md5_init

BYTES_READ=0
tot_bytes=0
declare -a CHUNK

fd=0

while true; do
  read_chunk $fd

  ((tot_bytes+=BYTES_READ))

  if [ $BYTES_READ -lt 64 ]; then
    # EOF, add padding

    #echo "final loop"

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

    ls4=$(( (tot_bytes * 8) & 16#ffffffff ))
    ms4=$(( ( (tot_bytes * 8) >> 32 ) & 16#ffffffff ))

    int_to_bytes_le ${ls4}
    declare -a temp=( $MD5_RESULT )
    padding[padding_len]=${temp[0]}
    padding[padding_len+1]=${temp[1]}
    padding[padding_len+2]=${temp[2]}
    padding[padding_len+3]=${temp[3]}

    int_to_bytes_le ${ms4}
    declare -a temp=( $MD5_RESULT )
    padding[padding_len+4]=${temp[0]}
    padding[padding_len+5]=${temp[1]}
    padding[padding_len+6]=${temp[2]}
    padding[padding_len+7]=${temp[3]}

    # now add padding to chunk, process as needed (1 or 2 times)
 
    padding_count=0
    while true; do

      #echo "bytes is $BYTES_READ"

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

for ((i=0; i< 4; i++)); do

  int_to_bytes_le ${MD5_WORDS[i]}
  declare -a temp=( $MD5_RESULT )
  printf -v t '%02x' "${temp[@]}"
  printf -v result '%s%s' "${result}" "${t}"

done

echo "$result"

