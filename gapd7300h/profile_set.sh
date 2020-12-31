#!/bin/sh

if [ "$#" != "1" ]; then
	echo 'error arg'
	echo 'arg is profile name. e.g. gapd7200 ...'
	exit 1
fi

if [ ! -f "davo/${1}/version.mk" ]; then
	echo no such profile $1.
	exit 2;
fi

echo '============================================'
echo "changing PROFILE to $1!!!!"
echo 'changing profile && feed update && copy .config'
echo 'if you unsure, do make clean'
echo '============================================'

sleep 3;

if [ ! -f ".config" ]; then
	cp davo/${1}/dot_config .config
fi

echo make package/feeds/dv_pkg/glite_oam/clean 
make package/feeds/dv_pkg/glite_oam/clean  > /dev/null 2> /dev/null
echo make package/feeds/dv_pkg/rtl8367r/clean
make package/feeds/dv_pkg/rtl8367r/clean  > /dev/null 2> /dev/null
echo make package/feeds/dv_pkg/dvbrdio/clean
make package/feeds/dv_pkg/dvbrdio/clean  > /dev/null 2> /dev/null
echo make package/feeds/dv_pkg/libdvct/clean
make package/feeds/dv_pkg/libdvct/clean  > /dev/null 2> /dev/null
echo make package/feeds/dv_pkg/dvmgmt/clean
make package/feeds/dv_pkg/dvmgmt/clean  > /dev/null 2> /dev/null
echo make package/feeds/dv_pkg/libdvapi/clean 
make package/feeds/dv_pkg/libdvapi/clean  > /dev/null 2> /dev/null
echo make package/feeds/ssdk/qca-ssdk/clean
make package/feeds/ssdk/qca-ssdk/clean  > /dev/null 2> /dev/null
echo package/feeds/ssdk/qca-ssdk-shell/clean
make package/feeds/ssdk/qca-ssdk-shell/clean > /dev/null 2> /dev/null


rm -f build_dir/target-arm_cortex-a7_uClibc-1.0.14_eabi/root-ipq806x/lib/modules/3.14.77/rtl8367r.ko;
rm -f build_dir/target-arm_cortex-a7_uClibc-1.0.14_eabi/root-ipq806x/usr/sbin/glite_oam;
rm -f CURRENT_PROFILE_*;

echo ./scripts/feeds update -a
./scripts/feeds update -a > /dev/null 2> /dev/null
echo ./scripts/feeds install -a -f
./scripts/feeds install -a -f > /dev/null 2> /dev/null

echo cp davo/${1}/dot_config .config
cp davo/${1}/dot_config .config
touch CURRENT_PROFILE_${1}

echo '============================================'
echo done!;
echo '============================================'
