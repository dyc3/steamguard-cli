#!/usr/bin/env bash

rsprotoc() { protoc "$@" --rust_out ../src/ --proto_path=./ --proto_path=/usr/include --proto_path=/usr/local/include ;}

cd protos

echo -n "" > ../src/lib.rs

for filename in *.proto; do
    rsprotoc $filename

    mod="${filename%.*}";
    mod="${mod//\./_}";
    echo "pub mod ${mod};" >> ../src/lib.rs
done