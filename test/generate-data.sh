# Get the current directory from CMake
root_dir=$1

# Prepare
mkdir -p "${root_dir}/data"

# make a random key for AES
dd if=/dev/urandom of="${root_dir}/data/key.bin" bs=16 count=1
dd if=/dev/urandom of="${root_dir}/data/iv.bin" bs=16 count=1
key=`od -t x1 -An "${root_dir}/data/key.bin" | tr -d '\n '`
iv=`od -t x1 -An "${root_dir}/data/iv.bin" | tr -d '\n '`

# Make a digital signature and a key pair
openssl genrsa -out "${root_dir}/data/rsa.private.pem" 2048
openssl rsa -in "${root_dir}/data/rsa.private.pem" -out "${root_dir}/data/rsa.public.pem" -pubout -outform PEM
rsaPrivate="${root_dir}/data/rsa.private.pem"
rsaPublic="${root_dir}/data/rsa.public.pem"

for i in `seq 1 100`
do
    plain="${root_dir}/data/plain-${i}.bin"
    cypher="${root_dir}/data/cypher-${i}.bin"
    sign="${root_dir}/data/old-sign-${i}.bin"

    size=`awk -v min=10 -v max=4096 'BEGIN{srand(); print int(min+rand()*(max-min+1))}'`
    dd if=/dev/urandom of=$plain bs=1 count=$size

    openssl enc -e -K $key -iv $iv -aes-128-cbc -in $plain -out $cypher
    openssl dgst -sha256 -sign $rsaPrivate -out $sign $plain
done

