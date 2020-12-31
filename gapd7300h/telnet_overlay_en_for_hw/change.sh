#!/bin/sh

do_cmd()
{
	echo Running $*
	$*
}

if [ "$#" != "1" ]; then
	echo 'error arg'
	echo 'arg is hw_test or org ...'
	exit 1
fi

echo '============================================'
echo "changing sdk to $1 !!"
echo '============================================'

if [ "$1" = "hw_test" ]; then 
	do_cmd cp telnetd.c ../build_dir/target-arm_cortex-a7_uClibc-1.0.14_eabi/busybox-1.25.1/networking/telnetd.c
	do_cmd cp mount_root.c ../build_dir/target-arm_cortex-a7_uClibc-1.0.14_eabi/fstools-2016-01-10/mount_root.c
	do_cmd cp dot_config ../.config
	do_cmd cp telnetd ../files/etc/init.d
elif [ "$1" = "org" ]; then 
	do_cmd svn revert ../build_dir/target-arm_cortex-a7_uClibc-1.0.14_eabi/busybox-1.25.1/networking/telnetd.c
	do_cmd svn revert ../build_dir/target-arm_cortex-a7_uClibc-1.0.14_eabi/fstools-2016-01-10/mount_root.c
	do_cmd cp dot_config.org ../.config
	do_cmd rm -f ../files/etc/init.d/telnetd
else
	echo "UNKNOWN"
	exit 1
fi

echo '============================================'
echo done!;
echo '============================================'



