#!/bin/bash

# debug

print_words_hex_32(){

  for((i = 0; i < ${#wl[@]}; i++)); do
    printf "%08x " ${wl[i]}
    if [ $i -ne 0 ] && [ $(( (i + 1) % 8 )) -eq 0 ]; then
      printf '\n'
    fi
  done
}

print_words_hex_64(){

  for((i = 0; i < ${#wh[@]}; i++)); do
    printf "%02d: %08x%08x\n" $i ${wh[i]} ${wl[i]}
  done

}


print_letters_hex_32(){

  printf '%08x ' "$@"
  printf '\n'
}

print_letters_hex_64(){

  printf '%08x%08x ' "$@"
  printf '\n'
}

# sums two 32-bit ints (representing a 64-bit int)
# to another two 32-bit ints (representing another 64-bit int)
# and store the result into two more 32-bits ints
sum_64bits(){

  local n1h=$1 n1l=$2 n2h=$3 n2l=$4

  local new_nh new_nl

  new_nl=$(( n1l + n2l ))
  carry=$(( new_nl >> 32 ))  # if any
  new_nh=$(( n1h + n2h + carry ))

  ensure_32bits $new_nh $new_nl
}


# rotates right with wraparound
# input is always nl, num. bits to rotate
right_rotate_32(){

  local nl=$1 s=$2
  local new_nl

  new_nl=$(( (nl >> s) | (nl << (32 - s)) ))
  ensure_32bits 0 $new_nl
}

# rotates right with wraparound
# two 32-bit words representing a 64-bit int
# input is always nh, nl, num. bits to rotate
right_rotate_64(){

  local nh=$1 nl=$2 s=$3

  local new_nh new_nl

  if [ $s -lt 32 ]; then
    new_nh=$(( (nh >> s) | (nl << (32 - s)) ))
    new_nl=$(( (nl >> s) | (nh << (32 - s)) ))
  else
    new_nh=$(( (nh << (64 - s)) | (nl >> (s - 32)) ))
    new_nl=$(( (nl << (64 - s)) | (nh >> (s - 32)) ))
  fi
  ensure_32bits $new_nh $new_nl

}

# plain shift right, no wraparound
right_shift_32(){
  local nl=$1 s=$2
  local new_nl

  new_nl=$(( nl >> s ))
  ensure_32bits 0 $new_nl
}

right_shift_64(){
  local nh=$1 nl=$2 s=$3
  local new_nl new_nh

  new_nh=$(( nh >> s ))
  if [ $s -lt 32 ]; then
    new_nl=$(( (nl >> s) | (nh << (32 - s) ) ))
  else
    new_nl=$(( (nh >> s) | (nh >> (s - 32)) ))
  fi
  ensure_32bits $new_nh $new_nl
}


# reduce everything to 32 bits (assumes bash uses (> 32)-bit integers)
ensure_32bits(){
  local high=$1 low=$2

  unset SHA2_RESULT
  SHA2_RESULT=( $(( high & 16#ffffffff )) $(( low & 16#ffffffff )) )
}


sha2_init(){

  local -a temp
  local elem low_start_pos

  SHA2_HWORDS=( 0 0 0 0 0 0 0 0 )
  SHA2_LWORDS=( 0 0 0 0 0 0 0 0 )

  low_start_pos=$(( (SHA2_BITS - 32) / 4 ))  #  32: 0, 64: 8

  for (( i = 0; i < ${#SHA2_WORDS_INITX[@]}; i++)); do
    elem=${SHA2_WORDS_INITX[$i]}
    #echo "${elem:$low_start_pos:8}"
    SHA2_LWORDS[$i]=$((16#${elem:$low_start_pos:8}))
    if [ $SHA2_BITS -eq 64 ]; then
      SHA2_HWORDS[$i]=$((16#${elem:0:8}))
    fi
  done

  # init K array
  KH=()
  KL=()

  for (( i = 0; i < ${#KX[@]}; i++)); do
    elem=${KX[$i]}
    KL[$i]=$(( 16#${elem:$low_start_pos:8} ))
    if [ $SHA2_BITS -eq 64 ]; then
      KH[$i]=$((16#${elem:0:8}))
     else
      KH[$i]=0
    fi
  done

}

read_chunk(){

  local data status length
  
  local fd=$1
  
  BYTES_READ=0
  CHUNK=()
  
  local chunk_size=$SHA2_CHUNK  # 32 bits: 512 bits (64 bytes), 64 bits: 1024 bits (128 bytes)
  local to_read=$chunk_size
  
  while true; do 
    IFS= read -u $fd -d '' -r -n $to_read data
    status=$?

    length=${#data}

    for ((i=0; i < length; i++)); do
      printf -v "CHUNK[BYTES_READ + i]" "%d" "'${data:i:1}"
    done

    # if we read less than we wanted, and it's not EOF, it means we also have
    # a delimiter
    if [ $length -lt $to_read ] && [ $status -eq 0 ]; then
      CHUNK[BYTES_READ + length]=0
      ((length++))
    fi

    ((BYTES_READ+=length))
    if [ $BYTES_READ -ge $chunk_size ]; then
      break
    fi
    if [ $status -ne 0 ]; then
      break
    fi
    ((to_read-=length))
  done

}

# turns the input bytes into a number (MSB is first argument)
# if the input is 4 elements, it's an (empty) high 4-byte int + a low 4-byte int
# if the input is 8 elements, it's a high 4-byte int + a low 4-byte int
bytes_to_int_msb(){

  local -a args result=(0 0)
  local i lhi byte

  # add extra zeros to always have 8 arguments
  for ((i = 0; i < 8 - $#; i++)); do
    args+=( 0 )
  done

  for (( i = 1; i <= $#; i++)); do
    args+=( ${!i} )
  done

  local -a result=(0 0)

  for ((i=0; i < 8; i++)); do
    byte=${args[$i]}
    lhi=$((i / 4))   # 0 for high, 1 for low
    shft=$(( ( (lhi * 4 + 3) - i) * 8  ))     # how much to shift left
    result[lhi]=$(( result[lhi] + (byte << shft) ))
  done

  unset SHA2_RESULT
  SHA2_RESULT=( "${result[@]}" )
}

# given an integer, convert it to 4/8/16 bytes (big endian)
# Assumes n is less than 2**63, blah, blah, blah
int_to_bytes_be(){

  local n=$1 nbytes=$2
  local i

  local nh nl

  nh=$(( (n & 16#ffffffff) >> 32 ))
  nl=$(( n & 16#ffffffff ))

  unset SHA2_RESULT
  SHA2_RESULT=()

  if [ $nbytes -eq 4 ]; then
    for ((i = 3; i>= 0; i--)); do
      SHA2_RESULT+=( $(( (nl >> (i * 8) ) & 16#ff )) )
    done
  else
    for ((i = 3; i>= 0; i--)); do
      SHA2_RESULT+=( $(( (nh >> (i * 8) ) & 16#ff )) )
    done
    for ((i = 3; i>= 0; i--)); do
      SHA2_RESULT+=( $(( (nl >> (i * 8) ) & 16#ff )) )
    done
  fi

  if [ $nbytes -eq 16 ]; then
    # cheating
    SHA2_RESULT=( 0 0 0 0 0 0 0 0 "${SHA2_RESULT[@]}" )
  fi
}

process_chunk(){

  local -a wh wl
  local -a p1 p2 p3 s0 s1

  local c=$(( SHA2_BITS / 8 ))   # 32: 4, 64: 8

  # CHUNK is 64/128 bytes, read 4/8 at a time
  # and copy them to w{h,l}

  # copy chunk into first 16 positions of wl
  # first 4/8 bytes will go into w{h,l}[0]
  # second 4/8 bytes will go into w{h,l}[1] etc.
  for ((count=0; count < 16; count++)); do
    bytes_to_int_msb "${CHUNK[@]:$count*$c:$c}"
    wh[count]=${SHA2_RESULT[0]}
    wl[count]=${SHA2_RESULT[1]}
  done

  #print_words_hex_${SHA2_BITS}
  #echo

  # extend with 48/64 extra words
  for ((count = 16; count < 64 + (16 * (SHA2_BITS == 64)); count++)); do

    if [ $SHA2_BITS -eq 32 ]; then

      right_rotate_32 ${wl[count - 15]} 7
      p1=( "${SHA2_RESULT[@]}" )

      right_rotate_32 ${wl[count - 15]} 18
      p2=( "${SHA2_RESULT[@]}" )

      right_shift_32 ${wl[count - 15]} 3
      p3=( "${SHA2_RESULT[@]}" )

      ensure_32bits 0 $(( p1[1] ^ p2[1] ^ p3[1] ))
      s0=( "${SHA2_RESULT[@]}" )
      
      right_rotate_32 ${wl[count - 2]} 17
      p1=( "${SHA2_RESULT[@]}" )
  
      right_rotate_32 ${wl[count - 2]} 19
      p2=( "${SHA2_RESULT[@]}" )
  
      right_shift_32 ${wl[count - 2]} 10
      p3=( "${SHA2_RESULT[@]}" )
  
      ensure_32bits 0 $(( p1[1] ^ p2[1] ^ p3[1] ))
      s1=( "${SHA2_RESULT[@]}" )
  
      # result from the above: s0 and s1
  
      ensure_32bits 0 $(( wl[count - 16] + s0[1] + wl[count - 7] + s1[1] ))
      wl[count]=${SHA2_RESULT[1]}
    else

      right_rotate_64 ${wh[count - 15]} ${wl[count - 15]} 1
      p1=( "${SHA2_RESULT[@]}" )

      right_rotate_64 ${wh[count - 15]} ${wl[count - 15]} 8
      p2=( "${SHA2_RESULT[@]}" )

      right_shift_64 ${wh[count - 15]} ${wl[count - 15]} 7
      p3=( "${SHA2_RESULT[@]}" )

      ensure_32bits $(( p1[0] ^ p2[0] ^ p3[0] )) $(( p1[1] ^ p2[1] ^ p3[1] ))
      s0=( "${SHA2_RESULT[@]}" )

      right_rotate_64 ${wh[count - 2]} ${wl[count - 2]} 19
      p1=( "${SHA2_RESULT[@]}" )
  
      right_rotate_64 ${wh[count - 2]} ${wl[count - 2]} 61
      p2=( "${SHA2_RESULT[@]}" )
  
      right_shift_64 ${wh[count - 2]} ${wl[count - 2]} 6
      p3=( "${SHA2_RESULT[@]}" )
  
      ensure_32bits $(( p1[0] ^ p2[0] ^ p3[0] )) $(( p1[1] ^ p2[1] ^ p3[1] ))
      s1=( "${SHA2_RESULT[@]}" )
  
      # result from the above: s0 and s1
 
      sum_64bits ${wh[count - 16]} ${wl[count - 16]} ${s0[0]} ${s0[1]}
      p1=( "${SHA2_RESULT[@]}" )

      sum_64bits ${p1[0]} ${p1[1]} ${wh[count - 7]} ${wl[count - 7]}
      p1=( "${SHA2_RESULT[@]}" )

      sum_64bits ${p1[0]} ${p1[1]} ${s1[0]} ${s1[1]}
      wh[count]=${SHA2_RESULT[0]}
      wl[count]=${SHA2_RESULT[1]}
    fi
  done

  local -a a=( ${SHA2_HWORDS[0]} ${SHA2_LWORDS[0]} )
  local -a b=( ${SHA2_HWORDS[1]} ${SHA2_LWORDS[1]} )
  local -a c=( ${SHA2_HWORDS[2]} ${SHA2_LWORDS[2]} )
  local -a d=( ${SHA2_HWORDS[3]} ${SHA2_LWORDS[3]} )
  local -a e=( ${SHA2_HWORDS[4]} ${SHA2_LWORDS[4]} )
  local -a f=( ${SHA2_HWORDS[5]} ${SHA2_LWORDS[5]} )
  local -a g=( ${SHA2_HWORDS[6]} ${SHA2_LWORDS[6]} )
  local -a h=( ${SHA2_HWORDS[7]} ${SHA2_LWORDS[7]} )

  local -a ch temp1 temp2 maj

  for ((round = 0; round < 64 + (16 * (SHA2_BITS == 64)); round++)); do

    if [ $SHA2_BITS -eq 32 ]; then

      right_rotate_32 ${e[1]} 6
      p1=( "${SHA2_RESULT[@]}" )
  
      right_rotate_32 ${e[1]} 11
      p2=( "${SHA2_RESULT[@]}" )
  
      right_rotate_32 ${e[1]} 25
      p3=( "${SHA2_RESULT[@]}" )
  
      ensure_32bits 0 $(( p1[1] ^ p2[1] ^ p3[1] ))
      s1=( "${SHA2_RESULT[@]}" )
  
      ensure_32bits 0 $(( ( e[1] & f[1] ) ^ (~e[1] & g[1]) ))
      ch=( "${SHA2_RESULT[@]}" )
  
      ensure_32bits 0 $(( h[1] + s1[1] + ch[1] + KL[round] + wl[round] ))
      temp1=( "${SHA2_RESULT[@]}" )
  
      right_rotate_32 ${a[1]} 2
      p1=( "${SHA2_RESULT[@]}" )
  
      right_rotate_32 ${a[1]} 13
      p2=( "${SHA2_RESULT[@]}" )
  
      right_rotate_32 ${a[1]} 22
      p3=( "${SHA2_RESULT[@]}" )
  
      ensure_32bits 0 $(( p1[1] ^ p2[1] ^ p3[1] ))
      s0=( "${SHA2_RESULT[@]}" )
  
      ensure_32bits 0 $(( (a[1] & b[1]) ^ (a[1] & c[1]) ^ (b[1] & c[1]) ))
      maj=( "${SHA2_RESULT[@]}" )
  
      ensure_32bits 0 $(( s0[1] + maj[1] ))
      temp2=( "${SHA2_RESULT[@]}" )
   
      h=( "${g[@]}" )
      g=( "${f[@]}" )
      f=( "${e[@]}" )
      ensure_32bits 0 $(( d[1] + temp1[1] ))
      e=( "${SHA2_RESULT[@]}" )
      d=( "${c[@]}" )
      c=( "${b[@]}" )
      b=( "${a[@]}" )
      ensure_32bits 0 $(( temp1[1] + temp2[1] ))
      a=( "${SHA2_RESULT[@]}" )

    else
      right_rotate_64 "${e[@]}" 14
      p1=( "${SHA2_RESULT[@]}" )
  
      right_rotate_64 "${e[@]}" 18
      p2=( "${SHA2_RESULT[@]}" )
  
      right_rotate_64 "${e[@]}" 41
      p3=( "${SHA2_RESULT[@]}" )

      ensure_32bits $(( p1[0] ^ p2[0] ^ p3[0] )) $(( p1[1] ^ p2[1] ^ p3[1] ))
      s1=( "${SHA2_RESULT[@]}" )
 
      ensure_32bits $(( ( e[0] & f[0] ) ^ (~e[0] & g[0]) ))  $(( ( e[1] & f[1] ) ^ (~e[1] & g[1]) ))
      ch=( "${SHA2_RESULT[@]}" )

      sum_64bits ${h[0]} ${h[1]} ${s1[0]} ${s1[1]}
      p1=( "${SHA2_RESULT[@]}" )

      sum_64bits ${p1[0]} ${p1[1]} ${ch[0]} ${ch[1]}
      p1=( "${SHA2_RESULT[@]}" )

      sum_64bits ${p1[0]} ${p1[1]} ${KH[round]} ${KL[round]}
      p1=( "${SHA2_RESULT[@]}" )

      sum_64bits ${p1[0]} ${p1[1]} ${wh[round]} ${wl[round]}
      temp1=( "${SHA2_RESULT[@]}" )
  
      right_rotate_64 "${a[@]}" 28
      p1=( "${SHA2_RESULT[@]}" )
  
      right_rotate_64 "${a[@]}" 34
      p2=( "${SHA2_RESULT[@]}" )
  
      right_rotate_64 "${a[@]}" 39
      p3=( "${SHA2_RESULT[@]}" )
   
      ensure_32bits $(( p1[0] ^ p2[0] ^ p3[0] )) $(( p1[1] ^ p2[1] ^ p3[1] ))
      s0=( "${SHA2_RESULT[@]}" )

      ensure_32bits $(( (a[0] & b[0]) ^ (a[0] & c[0]) ^ (b[0] & c[0]) ))  $(( (a[1] & b[1]) ^ (a[1] & c[1]) ^ (b[1] & c[1]) ))
      maj=( "${SHA2_RESULT[@]}" )
 
      sum_64bits ${s0[0]} ${s0[1]} ${maj[0]} ${maj[1]}
      temp2=( "${SHA2_RESULT[@]}" )
   
      h=( "${g[@]}" )
      g=( "${f[@]}" )
      f=( "${e[@]}" )

      sum_64bits ${d[0]} ${d[1]} ${temp1[0]} ${temp1[1]}
      e=( "${SHA2_RESULT[@]}" )

      d=( "${c[@]}" )
      c=( "${b[@]}" )
      b=( "${a[@]}" )

      sum_64bits ${temp1[0]} ${temp1[1]} ${temp2[0]} ${temp2[1]}
      a=( "${SHA2_RESULT[@]}" )

    fi

  done

  if [ $SHA2_BITS -eq 32 ]; then
    ensure_32bits 0 $(( SHA2_LWORDS[0] + a[1] ))
    SHA2_LWORDS[0]=${SHA2_RESULT[1]}
  
    ensure_32bits 0 $(( SHA2_LWORDS[1] + b[1] ))
    SHA2_LWORDS[1]=${SHA2_RESULT[1]}
    
    ensure_32bits 0 $(( SHA2_LWORDS[2] + c[1] ))
    SHA2_LWORDS[2]=${SHA2_RESULT[1]}
    
    ensure_32bits 0 $(( SHA2_LWORDS[3] + d[1] ))
    SHA2_LWORDS[3]=${SHA2_RESULT[1]}
    
    ensure_32bits 0 $(( SHA2_LWORDS[4] + e[1] ))
    SHA2_LWORDS[4]=${SHA2_RESULT[1]}
    
    ensure_32bits 0 $(( SHA2_LWORDS[5] + f[1] ))
    SHA2_LWORDS[5]=${SHA2_RESULT[1]}
    
    ensure_32bits 0 $(( SHA2_LWORDS[6] + g[1] ))
    SHA2_LWORDS[6]=${SHA2_RESULT[1]}
    
    ensure_32bits 0 $(( SHA2_LWORDS[7] + h[1] ))
    SHA2_LWORDS[7]=${SHA2_RESULT[1]}
  else
    sum_64bits ${SHA2_HWORDS[0]} ${SHA2_LWORDS[0]} ${a[0]} ${a[1]}
    SHA2_HWORDS[0]=${SHA2_RESULT[0]}
    SHA2_LWORDS[0]=${SHA2_RESULT[1]}

    sum_64bits ${SHA2_HWORDS[1]} ${SHA2_LWORDS[1]} ${b[0]} ${b[1]}
    SHA2_HWORDS[1]=${SHA2_RESULT[0]}
    SHA2_LWORDS[1]=${SHA2_RESULT[1]}

    sum_64bits ${SHA2_HWORDS[2]} ${SHA2_LWORDS[2]} ${c[0]} ${c[1]}
    SHA2_HWORDS[2]=${SHA2_RESULT[0]}
    SHA2_LWORDS[2]=${SHA2_RESULT[1]}

    sum_64bits ${SHA2_HWORDS[3]} ${SHA2_LWORDS[3]} ${d[0]} ${d[1]}
    SHA2_HWORDS[3]=${SHA2_RESULT[0]}
    SHA2_LWORDS[3]=${SHA2_RESULT[1]}

    sum_64bits ${SHA2_HWORDS[4]} ${SHA2_LWORDS[4]} ${e[0]} ${e[1]}
    SHA2_HWORDS[4]=${SHA2_RESULT[0]}
    SHA2_LWORDS[4]=${SHA2_RESULT[1]}

    sum_64bits ${SHA2_HWORDS[5]} ${SHA2_LWORDS[5]} ${f[0]} ${f[1]}
    SHA2_HWORDS[5]=${SHA2_RESULT[0]}
    SHA2_LWORDS[5]=${SHA2_RESULT[1]}

    sum_64bits ${SHA2_HWORDS[6]} ${SHA2_LWORDS[6]} ${g[0]} ${g[1]}
    SHA2_HWORDS[6]=${SHA2_RESULT[0]}
    SHA2_LWORDS[6]=${SHA2_RESULT[1]}

    sum_64bits ${SHA2_HWORDS[7]} ${SHA2_LWORDS[7]} ${h[0]} ${h[1]}
    SHA2_HWORDS[7]=${SHA2_RESULT[0]}
    SHA2_LWORDS[7]=${SHA2_RESULT[1]}
  
  fi
}

### BEGIN HERE

export LC_ALL=C

name="${0##*/}"

if [[ ! "$name" =~ ^sha(224|256|384|512(-(224|256))?)\.sh$ ]]; then
  echo "Cannot use $name to call this script" >&2
  exit 1
fi

SHA2_BITS=32
SHA2_CHUNK=64   # bytes

declare -a SHA2_WORDS_INITX
declare -a SHA2_LWORDS    # final hash will be here
declare -a SHA2_HWORDS    # and here (64-bit)

declare -a KX KL

if [ "$name" = "sha256.sh" ]; then

  SHA2_WORDS_INITX=( 6a09e667
                     bb67ae85
                     3c6ef372
                     a54ff53a
                     510e527f
                     9b05688c
                     1f83d9ab
                     5be0cd19 )

elif [ "$name" = "sha224.sh" ]; then

  SHA2_WORDS_INITX=( c1059ed8
                     367cd507
                     3070dd17
                     f70e5939
                     ffc00b31
                     68581511
                     64f98fa7
                     befa4fa4 )

elif [ "$name" = sha512.sh ]; then

  SHA2_BITS=64
  SHA2_CHUNK=128   # bytes

  SHA2_WORDS_INITX=( 6a09e667f3bcc908
                     bb67ae8584caa73b
                     3c6ef372fe94f82b
                     a54ff53a5f1d36f1
                     510e527fade682d1
                     9b05688c2b3e6c1f
                     1f83d9abfb41bd6b
                     5be0cd19137e2179 )

elif [ "$name" = "sha512-224.sh" ]; then

  SHA2_BITS=64
  SHA2_CHUNK=128   # bytes

  SHA2_WORDS_INITX=( 8c3d37c819544da2
                     73e1996689dcd4d6
                     1dfab7ae32ff9c82
                     679dd514582f9fcf
                     0f6d2b697bd44da8
                     77e36f7304c48942
                     3f9d85a86a1d36c8
                     1112e6ad91d692a1 )

elif [ "$name" = "sha512-256.sh" ]; then

  SHA2_BITS=64
  SHA2_CHUNK=128   # bytes

  SHA2_WORDS_INITX=( 22312194fc2bf72c
                     9f555fa3c84c64c2
                     2393b86b6f53b151
                     963877195940eabd
                     96283ee2a88effe3
                     be5e1e2553863992
                     2b0199fc2c85b8aa
                     0eb72ddc81c52ca2 )

elif [ "$name" = sha384.sh ]; then

  SHA2_BITS=64
  SHA2_CHUNK=128   # bytes

  SHA2_WORDS_INITX=( cbbb9d5dc1059ed8
                     629a292a367cd507
                     9159015a3070dd17
                     152fecd8f70e5939
                     67332667ffc00b31
                     8eb44a8768581511
                     db0c2e0d64f98fa7
                     47b5481dbefa4fa4 )

fi

if [[ "$name" =~ ^sha(256|224)\.sh$ ]]; then

  KX=( 428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
       d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174
       e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da
       983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967
       27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85
       a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070
       19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3
       748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2 )

elif [[ "$name" =~ ^sha(512(-(224|256))?|384)\.sh$ ]]; then

  KX=( 428a2f98d728ae22 7137449123ef65cd b5c0fbcfec4d3b2f e9b5dba58189dbbc
       3956c25bf348b538 59f111f1b605d019 923f82a4af194f9b ab1c5ed5da6d8118
       d807aa98a3030242 12835b0145706fbe 243185be4ee4b28c 550c7dc3d5ffb4e2
       72be5d74f27b896f 80deb1fe3b1696b1 9bdc06a725c71235 c19bf174cf692694
       e49b69c19ef14ad2 efbe4786384f25e3 0fc19dc68b8cd5b5 240ca1cc77ac9c65
       2de92c6f592b0275 4a7484aa6ea6e483 5cb0a9dcbd41fbd4 76f988da831153b5
       983e5152ee66dfab a831c66d2db43210 b00327c898fb213f bf597fc7beef0ee4
       c6e00bf33da88fc2 d5a79147930aa725 06ca6351e003826f 142929670a0e6e70
       27b70a8546d22ffc 2e1b21385c26c926 4d2c6dfc5ac42aed 53380d139d95b3df
       650a73548baf63de 766a0abb3c77b2a8 81c2c92e47edaee6 92722c851482353b
       a2bfe8a14cf10364 a81a664bbc423001 c24b8b70d0f89791 c76c51a30654be30
       d192e819d6ef5218 d69906245565a910 f40e35855771202a 106aa07032bbd1b8
       19a4c116b8d2d0c8 1e376c085141ab53 2748774cdf8eeb99 34b0bcb5e19b48a8
       391c0cb3c5c95a63 4ed8aa4ae3418acb 5b9cca4f7763e373 682e6ff3d6b2b8a3
       748f82ee5defb2fc 78a5636f43172f60 84c87814a1f0ab72 8cc702081a6439ec
       90befffa23631e28 a4506cebde82bde9 bef9a3f7b2c67915 c67178f2e372532b
       ca273eceea26619c d186b8c721c0c207 eada7dd6cde0eb1e f57d4f7fee6ed178
       06f067aa72176fba 0a637dc5a2c898a6 113f9804bef90dae 1b710b35131c471b
       28db77f523047d84 32caab7b40c72493 3c9ebe0a15c9bebc 431d67c49c100d4c
       4cc5d4becb3e42b6 597f299cfc657e2a 5fcb6fab3ad6faec 6c44198c4a475817 )

fi

sha2_init

tot_bytes=0        # total bytes read
declare -a CHUNK   # source data will go here

fd=0

while true; do
  read_chunk $fd

  ((tot_bytes+=BYTES_READ))

  if [ $BYTES_READ -lt $SHA2_CHUNK ]; then
    # EOF, add padding

    length_len=$((SHA2_BITS / 4))   # 32 bit: 8 bytes, 64 bit: 16 bytes
    multiple=$SHA2_CHUNK            # final message must be multiple of 64/128 bytes

    # find next multiple of $multiple bytes, taking into account that the last $length_len bytes are for length
    length_with_padding=$(( tot_bytes + 1 + length_len ))

    if [ $(( length_with_padding % multiple )) -ne 0 ]; then
      length_with_padding=$(( ((length_with_padding + multiple) / multiple) * multiple ))
    fi

    # how many bytes of 0 padding (without length)
    padding_len=$(( length_with_padding - length_len - tot_bytes ))

    declare -a padding

    # first bit must be 1...
    padding[0]=$(( 16#80 ))

    for (( byte = 1; byte < padding_len; byte++ )); do
      padding[byte]=0
    done

    # add length of the original message, IN BITS, encoded as 8/16 bytes, big-endian

    # plain tot_bytes * 8 _could_ be too big for a 64-bit signed int.
    # If you encounter this bug, let me know :-)
    msg_len=$(( tot_bytes * 8 ))

    declare -a length_bytes    # 8/16-byte array

    int_to_bytes_be $msg_len $length_len
    length_bytes=( "${SHA2_RESULT[@]}" )

    for ((i = 0; i < ${#length_bytes[@]}; i++)); do
      padding[padding_len + i]=${length_bytes[i]}
    done
 
    # now add padding to chunk, process as needed (1 or 2 times)
 
    padding_count=0
    while true; do

      CHUNK[$BYTES_READ]=${padding[$padding_count]}
      ((padding_count++))
      ((BYTES_READ++))

      if [ $BYTES_READ -ge $SHA2_CHUNK ]; then
        process_chunk
        CHUNK=()
        BYTES_READ=0
      fi

      if [ $padding_count -ge $(( padding_len + (SHA2_BITS / 4) )) ]; then
        break 2
      fi

    done

  else
    process_chunk
  fi
done

output=

upper=8
if [ "$name" = "sha224.sh" ]; then
  upper=7
elif [ "$name" = "sha384.sh" ]; then
  upper=6
elif [ "$name" = "sha512-224.sh" ] || [ "$name" = "sha512-256.sh" ]; then
  upper=4
fi

declare -a temp
for ((i=0; i < upper; i++)); do
  if [ $SHA2_BITS -eq 64 ]; then
    int_to_bytes_be ${SHA2_HWORDS[i]} 4
    temp=( "${SHA2_RESULT[@]}" )
    printf -v t '%02x' "${temp[@]}"
    printf -v output '%s%s' "${output}" "${t}"
  fi
  # stupid condition for sha512-224 only
  if [ "$name" != "sha512-224.sh" ] || [ $i -lt $(( upper - 1 )) ]; then
    int_to_bytes_be ${SHA2_LWORDS[i]} 4
    temp=( "${SHA2_RESULT[@]}" )
    printf -v t '%02x' "${temp[@]}"
    printf -v output '%s%s' "${output}" "${t}"
  fi
done

echo "$output"

