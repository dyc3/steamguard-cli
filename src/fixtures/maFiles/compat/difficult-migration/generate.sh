#!/bin/bash

cat "1234.maFile" | jq -r '.Session | keys | .[]' | while read key; do
	cat "1234.maFile" | jq ".Session[\"$key\"] = null" > "null-$key.maFile"
	cat "1234.maFile" | jq ". | del(.Session.$key)" > "missing-$key.maFile"
done
