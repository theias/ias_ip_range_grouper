#!/bin/bash

bin_whence="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cat $bin_whence/longer.txt \
| $bin_whence/../src/bin/ias_ip_range_grouper.pl \
	--cidr-grep \
	--cidr-include '192.168.0.0/8'
