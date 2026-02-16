#!/bin/bash
while true; do
    gdbserver 0.0.0.0:1234 php -d extension=./metadata_reader.so -S 0.0.0.0:8000
done
