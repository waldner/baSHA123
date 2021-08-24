#!/bin/bash

# copies arr2 onto arr1
copy(){

  local -n arr1=$1
  local -n arr2=$2

  arr1=( "${arr2[@]}" )

}

sha3_init(){

  local i r

  # init state
  for ((i=0; i < 200; i++)); do
    STATE[i]=0
  done

  for ((i = 0; i < 24; i++)); do
    local -n RC=RC_${i}
    r=${RCL[i]}
    RC[0]=$((16#${r:0:8}))
    RC[1]=$((16#${r:8:8}))
  done
}

not64(){
  local -n arr=$1
  arr[0]=$(( (~arr[0]) & 16#ffffffff ))
  arr[1]=$(( (~arr[1]) & 16#ffffffff ))
}

# and between two 8-byte arrays
# result in the first array
and64(){
  local -n arr1=$1
  local -n arr2=$2
  arr1[0]=$(( arr1[0] & arr2[0] ))
  arr1[1]=$(( arr1[1] & arr2[1] ))
}

# xor between two 8-byte arrays
# result in the first array
xor64(){
  local -n arr1=$1
  local -n arr2=$2
  arr1[0]=$(( arr1[0] ^ arr2[0] ))
  arr1[1]=$(( arr1[1] ^ arr2[1] ))
}

# rotate left an 8-bytes array by n bits
rol64_n(){
  local bits=$2
  local i
  for ((i = 0; i < bits; i++)); do
    rol64_1 $1
  done
}

# shift left 1 bit
rol64_1(){
  local -n arr=$1
  local b0=$(( arr[0] >> 31 ))
  local b1=$(( arr[1] >> 31 ))
  arr[0]=$(( (arr[0] << 1) & 16#ffffffff ))
  arr[0]=$(( arr[0] | b1 ))
  arr[1]=$(( (arr[1] << 1) & 16#ffffffff ))
  arr[1]=$(( arr[1] | b0 ))
}

process_chunk(){

  # xor chunk with first SHA3_CHUNK bytes of state
  for ((i=0; i < SHA3_CHUNK; i++)); do
    STATE[i]=$((STATE[i] ^ CHUNK[i]))
  done

  keccak_f_1600

}

keccak_f_1600(){

  # STATE is to be considered an array of 5 x 5 x 8 bytes (200 total)
  # each 8-byte group is a "lane", as follows

  # lane 0, 0 is state[0..7]
  # lane 0, 1 is state[40..47]
  # lane 0, 2 is state[80..87]
  # lane 0, 3 is state[120..127]
  # lane 0, 4 is state[160..167]

  # lane 1, 0 (5) is state[8..15]
  # lane 1, 1 (6) is state[48..55]
  # lane 1, 2 (7) is state[88..95]
  # lane 1, 3 (8) is state[128..135]
  # lane 1, 4 (9) is state[168..175]

  # ...

  # lane 4, 0 (20) is state[32..39]
  # lane 4, 1 (21) is state[72..79]
  # lane 4, 2 (22) is state[112..119]
  # lane 4, 3 (23) is state[152..159]
  # lane 4, 4 (24) is state[192..199]

  # bash might overflow with unsigned 64-bit values
  # so we use 25 arrays of 2x32 bytes values

  local x y j t

  for ((x = 0; x < 5; x++)); do
    for ((y = 0; y < 5; y++)); do
      local -a lane_${x}_${y}
      local -n lane=lane_${x}_${y}
      lane=()

      local base=$(( 8*(x+5*y) ))   # where lane starts in STATE

      for ((i = 7; i >= 0; i--)); do

        local index=$(( i > 3 ? 0 : 1 ))
        local shift
        if [ $i -gt 3 ]; then
          shift=$(( (i - 4) * 8 ))
        else
          shift=$((i * 8 ))
        fi

        # lane[0] gets bytes at base+7 (<< 24), base+6 (<< 16), base+5 (<< 8), base+4
        # lane[1] gets bytes at base+3 (<< 24), base+2 (<< 16), base+1 (<< 8), base+0

        lane[$index]=$(( lane[index] | (STATE[base + i] << shift) ))
      done
    done
  done

  for ((round = 0; round < 24; round++)); do

    # θ
    local -a C_0 C_1 C_2 C_3 C_4

    # C[x] = lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4]
    for ((x = 0; x < 5; x++)); do

      local -a C_${x}
      local -n C=C_${x}

      C=( 0 0 )
      for ((j = 0; j < 5; j++)); do
        local -n lane_x_j=lane_${x}_${j}
        xor64 C lane_x_j
      done
    done

    local -a D_0 D_1 D_2 D_3 D_4

    # D[x] = C[(x+4)%5] ^ ROL64(C[(x+1)%5], 1)
    for ((x = 0; x < 5; x++)); do

      local -a V1=()
      local -a V2=()

      # make copies
      copy V1 C_$(( (x + 4) % 5 ))
      copy V2 C_$(( (x + 1) % 5 ))

      rol64_1 V2

      local -n D=D_${x}

      D=( "${V1[@]}" )

      xor64 D V2
    done

    for ((x = 0; x < 5; x++)); do
        local -n D=D_${x}
        for ((y = 0; y < 5; y++)); do
            local -n lane=lane_${x}_${y}
            xor64 lane D
        done
    done

    # ρ and π
    x=1 y=0
    local -n current=lane_${x}_${y}
    local tmp
    local -a tmpa

    for ((t = 0; t < 24; t++)); do
      tmp=$x
      x=$y
      y=$(( (2 * tmp + 3 * y) % 5 ))

      copy tmpa current
      copy current lane_${x}_${y}
      rol64_n tmpa $(( (t + 1) * (t + 2) / 2 ))
      copy lane_${x}_${y} tmpa

    done

    # χ
    for ((y = 0; y < 5; y++)); do
      local -a T_0 T_1 T_2 T_3 T_4
      for ((x = 0; x < 5; x++)); do
          copy T_${x} lane_${x}_${y}
      done

      for ((x = 0; x < 5; x++)); do
         local -a T_OP1
         local -a T_OP2
         copy T_OP1 T_$(( (x + 1) % 5 ))
         copy T_OP2 T_$(( (x + 2) % 5 ))
         copy T_x T_${x}

         not64 T_OP1
         and64 T_OP1 T_OP2 

         xor64 T_x T_OP1
         copy lane_${x}_${y} T_x
      done
    done
 
    # ι
    xor64 lane_0_0 RC_${round}

  done

  # put lanes back into state
  for ((x = 0; x < 5; x++)); do
    for ((y = 0; y < 5; y++)); do
      local -a lane_${x}_${y}
      local -n lane=lane_${x}_${y}

      local base=$(( 8*(x+5*y) ))   # where lane starts in STATE

      for ((i = 0; i < 8; i++)); do

        local index=$(( i > 3 ? 0 : 1 ))
        local shift
        if [ $i -gt 3 ]; then
          shift=$(( (i - 4) * 8 ))
        else
          shift=$((i * 8))
        fi

        mask=$(( 16#ff << shift ))

        # STATE[base+0] gets bytes at (lanes[1] & ff) >> 0
        # STATE[base+1] gets bytes at (lanes[1] & ff00) >> 8
        # STATE[base+2] gets bytes at (lanes[1] & ff0000) >> 16
        # STATE[base+3] gets bytes at (lanes[1] & ff000000) >> 24
        # STATE[base+4] gets bytes at (lanes[0] & ff) >> 0
        # STATE[base+5] gets bytes at (lanes[0] & ff00) >> 8
        # STATE[base+6] gets bytes at (lanes[0] & ff0000) >> 16
        # STATE[base+7] gets bytes at (lanes[0] & ff000000) >> 24

        STATE[base+i]=$(( (lane[index] & mask) >> shift ))
      done
    done
  done
}


read_chunk(){

  local data status length

  local fd=$1

  BYTES_READ=0
  CHUNK=()

  local chunk_size=$SHA3_CHUNK    # this is "capacity"
  local to_read=$chunk_size

  while true; do
    IFS= read -u $fd -d '' -r -n $to_read data
    status=$?

    length=${#data}

    for ((i=0; i < length; i++)); do
      printf -v "CHUNK[BYTES_READ + i]" "%d" "'${data:i:1}"
    done

    # if we read less than we wanted, and it's not EOF, it means we also have
    # a delimiter (ie, a \0 byte)
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


###### BEGIN HERE

export LC_ALL=C

name=$(basename "$0")

if [[ ! "$name" =~ ^sha(3-(224|256|384|512)|ke(128|256))\.sh$ ]]; then
  echo "Cannot use $name to call this script" >&2
  exit 1
fi


if [ "$name" = "sha3-224.sh" ]; then
  SHA3_CAPACITY=1152    # bits, aka "r" in the docs, 144 bytes
  SHA3_RATE=448         # bits, aka "c" in the docs
  SHA3_PADDING=6
  SHA3_OUTPUT_LEN=28
elif [ "$name" = "sha3-256.sh" ]; then
  SHA3_CAPACITY=1088    # bits, 136 bytes
  SHA3_RATE=512         # bits
  SHA3_PADDING=6
  SHA3_OUTPUT_LEN=32
elif [ "$name" = "sha3-384.sh" ]; then
  SHA3_CAPACITY=832    # bits, 104 bytes
  SHA3_RATE=768        # bits
  SHA3_PADDING=6
  SHA3_OUTPUT_LEN=48
elif [ "$name" = "sha3-512.sh" ]; then
  SHA3_CAPACITY=576    # bits, 72 bytes
  SHA3_RATE=1024       # bits
  SHA3_PADDING=6
  SHA3_OUTPUT_LEN=64
elif [ "$name" = "shake128.sh" ]; then
  SHA3_CAPACITY=1344    # bits, 168 bytes
  SHA3_RATE=256         # bits
  SHA3_PADDING=31
  SHA3_OUTPUT_LEN=16
  if [ "$1" != "" ]; then
    SHA3_OUTPUT_LEN=$1
  fi
elif [ "$name" = "shake256.sh" ]; then
  SHA3_CAPACITY=1088    # bits, 136 bytes
  SHA3_RATE=512         # bits
  SHA3_PADDING=31
  SHA3_OUTPUT_LEN=32
  if [ "$1" != "" ]; then
    SHA3_OUTPUT_LEN=$1
  fi
fi

SHA3_CHUNK=$(( SHA3_CAPACITY / 8 ))  ## "r" in bytes
# in practice: 144, 136, 104, 72, 168, 136 bytes

declare -a CHUNK   # source data will go here

declare -a STATE  # 200 bytes / 1600 bits

declare -a RCL=(
  0000000000000001
  0000000000008082
  800000000000808A
  8000000080008000
  000000000000808B
  0000000080000001
  8000000080008081
  8000000000008009
  000000000000008A
  0000000000000088
  0000000080008009
  000000008000000A
  000000008000808B
  800000000000008B
  8000000000008089
  8000000000008003
  8000000000008002
  8000000000000080
  000000000000800A
  800000008000000A
  8000000080008081
  8000000000008080
  0000000080000001
  8000000080008008
)


sha3_init 

fd=0
BYTES_READ=0

# absorbing phase
while true; do
  read_chunk $fd

  eof=0

  if [ $BYTES_READ -lt $SHA3_CHUNK ]; then
    eof=1
    # EOF, add padding
    CHUNK[$BYTES_READ]=$SHA3_PADDING
    ((BYTES_READ++))

    while [ $BYTES_READ -lt $SHA3_CHUNK ]; do
      CHUNK[$BYTES_READ]=0
      ((BYTES_READ++))
    done
    CHUNK[$BYTES_READ-1]=$((CHUNK[BYTES_READ-1] ^ 128)) 
    
  fi

  process_chunk
  
  if [ $eof -eq 1 ]; then
    break
  fi
done

# squeeze phase (in most cases one repetition is enough)
while [ $SHA3_OUTPUT_LEN -gt 0 ]; do

  # minimum between SHA3_CHUNK and SHA3_OUTPUT_LEN
  if [ $SHA3_CHUNK -lt $SHA3_OUTPUT_LEN ]; then
    osize=$SHA3_CHUNK
  else
    osize=$SHA3_OUTPUT_LEN
  fi

  printf '%02x' "${STATE[@]:0:osize}"

  SHA3_OUTPUT_LEN=$(( SHA3_OUTPUT_LEN - osize ))

  if [ $SHA3_OUTPUT_LEN -gt 0 ]; then
    keccak_f_1600
  fi
done

echo
