#!/bin/bash

target="bandit24"

# Non riesce a scrivere sulla home di bandit23
path="/tmp/asdrubalebarca"

echo "Reading and saving file content..."

mkdir $path
touch $path/psw.txt
chmod 666 $path/psw.txt

cat /etc/bandit_pass/$target > $path/psw.txt
