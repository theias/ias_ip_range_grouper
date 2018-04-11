#!/bin/bash

F=$1

while IFS='' read -r line || [[ -n "$line" ]]; do
	echo $line
	sleep 1
done < "$F"
