#!/bin/bash

lineno=1
tmpf=""

error_die() {
	echo "$@"
	[ -e "$tmpf" ] && rm "$tmpf"
	exit 1
}

range() {
	local from to len i b val tmp

	tmp=$1
	from=${tmp/%-*/}
	to=${tmp/#*-/}
	let "len = $from - $to + 1"
	[ ${len} -le 0 -o ${len} -ge 32 ] && error_die "invalid bit range at ${lineno} line"
	tmp=$2
	[ ${len} -ne ${#tmp} ] && error_die "bit count mismatched at ${lineno} line"
	val=0
	i=0
	while [ $i -lt $len ]; do
		b=${tmp:$i:1}
		let "val <<= 1"
		let "val |= $b"
		((i += 1))
	done
	eval $3=$to
	eval $4=$len
	eval $5=$val
}

parse_line() {
	local alpha digit pinno offset mask_len value al tmp

	[ "$#" -ne 4 -a "$#" -ne 5 ] && error_die "argument must be 4 or 5 at ${lineno} line"

	[ "$#" -eq 5 -a "$5" != "0" -a "$5" != "1" ] && error_die "5th argument should be 0 or 1 at ${lineno} line"

	tmp=$(echo $1 | tr '[a-z]' '[A-Z]')
	alpha=${tmp:0:1}
	digit=${tmp:1:1}

	pinno=$2

	range $3 $4 offset mask_len value
	al=$5
	echo "{ .alpha = '${alpha}', .digit = ${digit}, .offset = $offset, .pinno = $pinno, .active_low = ${al:-0}, .mask_len = $mask_len, .value = $value }," >> $tmpf
}

mux2c() {
	tmpf=$(mktemp /tmp/XXXXXX)

	while read -r line; do
		[ -z "$line" ] && continue
		parse_line $(echo "$line" | tr ',' ' ')
		((lineno += 1))
	done < "$1"

	mv $tmpf $2
}

[ "$#" -ne 2 ] && exit 1
mux2c $1 $2
exit 0
