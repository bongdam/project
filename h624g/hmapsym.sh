#!/bin/sh

linux_base_dir=$1
altered=0

build_again() {
	echo "Just hard-mapped to local symbols. please rebuild linux"
	exit 1
}

symbol_remap() {
	local new_address old_address

	new_address=`grep " $1$" $linux_base_dir/System.map | awk -F " " '{printf "%s", $1}'`
	old_address=`grep "\(\s*\*\s*$1\s*\)" $2 | awk -F "0x" '{printf "%.8s", $2}'`
	if [ "x$old_address" != "x" ] && [ "$new_address" != "$old_address" ]; then
		sed -i -r "s/(.+$1.+0x)([0-9a-fA-Z]+)/\1$new_address/" $2
		altered=$(($altered + 1))
	fi
}

symbol_remap nat_tbl $linux_base_dir/drivers/net/rtl819x/davolink/rtl_davo_proc.c
symbol_remap _rtl865x_getNaptHashInfo $linux_base_dir/drivers/net/rtl819x/davolink/rtl_davo_proc.c
[ $altered -gt 0 ] && build_again || exit 0
