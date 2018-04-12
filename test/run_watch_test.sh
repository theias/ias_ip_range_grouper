#!/bin/bash

bin_whence="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

$bin_whence/one_by_one.sh $bin_whence/longer.txt \
| $bin_whence/../src/bin/ias_ip_range_grouper.pl \
    --watch \
    --watch-title "Watch test.  longer.txt" \
    --hit-count
