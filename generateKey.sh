#!/bin/bash
key=$(echo $RANDOM | md5sum | awk {'print $1'})

echo "{" > keys.json
echo "  \"1\":\"$key\"" >> keys.json
echo "}" >> keys.json

mkdir clefs > /dev/null 2>&1
