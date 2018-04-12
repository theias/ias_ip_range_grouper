#!/bin/bash

bin_whence="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# cat some_ip_list.txt | ../src/bin/ias_ip_range_grouper.pl --dump-binary

cat $bin_whence/some_ip_list.txt \
| $bin_whence/../src/bin/ias_ip_range_grouper.pl --dump-binary
