#!/bin/bash

# while true 
# do 
#     php -S 0.0.0.0:8000 -dextension=./metadata_reader.so
# done

# Get the absolute path of the current directory
DIR="$(cd "$(dirname "$0")" && pwd)"
while true; do
    php -S 0.0.0.0:8000 -d extension="$DIR/metadata_reader.so"
done

