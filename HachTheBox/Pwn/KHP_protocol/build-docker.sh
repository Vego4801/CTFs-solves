#!/bin/sh
docker build --tag=khp_protocol .
# Uncomment to open a port for gdbserver
# docker run -it -p 1337:1337 -p 4444:4444 --rm --name=khp_protocol khp_protocol
docker run -it -p 1337:1337 --rm --name=khp_protocol khp_protocol
