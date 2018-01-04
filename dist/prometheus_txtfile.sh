#!/bin/sh

usock_path="$1"

stats=$(nc -U "$usock_path")
iface=$(echo "$usock_path" | awk -F. '{print $(NF-1)}')

for line in $stats; do
	identifier=$(echo "$line" | cut -d ":" -f 1)
	bytes=$(echo "$line" | cut -d ":" -f 2)
	packets=$(echo "$line" | cut -d ":" -f 3)

	echo "bpfcountd_packets{iface=\"$iface\",$identifier} $packets"
	echo "bpfcountd_bytes{iface=\"$iface\",$identifier} $bytes"
done
