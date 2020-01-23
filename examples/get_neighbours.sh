#!/bin/bash

let n=1
input="/home/quic/ngtcp2_scache/examples/neighbours"
while IFS= read -r line
do
	sudo sshfs -o allow_other,default_permissions quic@$line:/home/quic/cache/ /home/quic/mnt$n/
	let n++
done < "$input"
