#!/bin/sh

# $1: wrt config (input)
# $2: mod_to_embed config (input)
# $3: mod from wrt (output temp)
# $4: linux_config

WRT_F=$1
MOD_DEF=$2
WRT_M_F=$3
LNX_CFG=$4

if [ ! -e $MOD_DEF ]; then
	touch $MOD_DEF
fi
grep '=m' $WRT_F > $WRT_M_F
for s in `cat $WRT_M_F`; do
	NEWVAR=`echo $s | sed 's/=m/=y/g'`
	grep -q $s $MOD_DEF
	if [ "$?" == "0" ]; then
		sed "s/$s/$NEWVAR/g" -i $LNX_CFG
	fi
done


