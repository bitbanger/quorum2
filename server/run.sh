#!/bin/bash

for id in $(seq 0 15)
do
	./server ${id} $(cat privkeys/privkey_${id}) ../addrs_pubkeys &
done

