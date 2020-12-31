#!/bin/sh

echo ======= pre_build_image $1
 
ROMFS=$1

#
# move usb releated kernel modules to another location for late loading
#
ROMFS_MOD_USB=$ROMFS/etc/modules-usb.d
ROMFS_MOD=$ROMFS/etc/modules.d
ROMFS_MOD_BOOT=$ROMFS/etc/modules-boot.d

FILES="20-usb-core 45-usb-gadget 45-usb-phy-dwc3-ipq40xx 45-usb-phy-dwc3-qcom 50-ledtrig-usbdev 53-usb-dwc3-ipq40xx 53-usb-dwc3-qcom 54-usb-dwc3 54-usb3 usb-acm"

mkdir -p $ROMFS_MOD_USB

for f in $FILES; do
	mv $ROMFS_MOD/$f $ROMFS_MOD_USB/$f
	rm -f $ROMFS_MOD_BOOT/$f
done

#
# hotplug.d : remove unused scripts
#
mkdir -p  $ROMFS/etc/hotplug.d/unused
mkdir -p  $ROMFS/etc/hotplug.d/unused_iface

mv $ROMFS/etc/hotplug.d/block $ROMFS/etc/hotplug.d/unused

mv $ROMFS/etc/hotplug.d/iface/15-teql $ROMFS/etc/hotplug.d/unused_iface
#mv $ROMFS/etc/hotplug.d/iface/30-repacd $ROMFS/etc/hotplug.d/unused_iface
mv $ROMFS/etc/hotplug.d/iface/55-mcproxy $ROMFS/etc/hotplug.d/unused_iface
mv $ROMFS/etc/hotplug.d/iface/90-rngd $ROMFS/etc/hotplug.d/unused_iface
mv $ROMFS/etc/hotplug.d/iface/98-snmp $ROMFS/etc/hotplug.d/unused_iface

#
# init.d : remove unused scripts
#
mkdir -p  $ROMFS/etc/init.d_unused
mkdir -p  $ROMFS/etc/rc.d_unused

mv $ROMFS/etc/init.d/dhcpr $ROMFS/etc/init.d_unused
mv $ROMFS/etc/init.d/dhcrelay4 $ROMFS/etc/init.d_unused
#mv $ROMFS/etc/init.d/lbd $ROMFS/etc/init.d_unused
mv $ROMFS/etc/init.d/led $ROMFS/etc/init.d_unused
mv $ROMFS/etc/init.d/macsec $ROMFS/etc/init.d_unused
mv $ROMFS/etc/init.d/mcproxy $ROMFS/etc/init.d_unused
mv $ROMFS/etc/init.d/multiwan $ROMFS/etc/init.d_unused
mv $ROMFS/etc/init.d/odhcpd $ROMFS/etc/init.d_unused
mv $ROMFS/etc/init.d/sysfixtime $ROMFS/etc/init.d_unused
mv $ROMFS/etc/init.d/sysntpd $ROMFS/etc/init.d_unused
mv $ROMFS/etc/init.d/telnet $ROMFS/etc/init.d_unused
mv $ROMFS/etc/init.d/thermal $ROMFS/etc/init.d_unused
mv $ROMFS/etc/init.d/wsplcd $ROMFS/etc/init.d_unused

mv $ROMFS/etc/rc.d/S18dhcpr $ROMFS/etc/rc.d_unused
mv $ROMFS/etc/rc.d/S91dhcrelay4 $ROMFS/etc/rc.d_unused
#mv $ROMFS/etc/rc.d/S55lbd $ROMFS/etc/rc.d_unused
mv $ROMFS/etc/rc.d/S96led $ROMFS/etc/rc.d_unused
mv $ROMFS/etc/rc.d/S98mcproxy $ROMFS/etc/rc.d_unused
mv $ROMFS/etc/rc.d/S98multiwan $ROMFS/etc/rc.d_unused
mv $ROMFS/etc/rc.d/S00sysfixtime $ROMFS/etc/rc.d_unused
mv $ROMFS/etc/rc.d/S98sysntpd $ROMFS/etc/rc.d_unused
mv $ROMFS/etc/rc.d/S50telnet $ROMFS/etc/rc.d_unused
mv $ROMFS/etc/rc.d/S98thermal $ROMFS/etc/rc.d_unused
mv $ROMFS/etc/rc.d/S52wsplcd $ROMFS/etc/rc.d_unused
rm $ROMFS/etc/banner
rm $ROMFS/etc/banner.failsafe

exit 0
