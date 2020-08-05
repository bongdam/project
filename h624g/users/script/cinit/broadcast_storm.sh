#!/bin/sh  
#                                 
# script file to start BroadcastStorm Control

BROADCAST_STORM_ENABLE=`nvram get x_BCSTORM_CTRL_ENABLE`
if [ "$BROADCAST_STORM_ENABLE" == "" ]; then
	exit 1
fi

BROADCAST_STORM_BPS=`nvram get x_BCSTORM_CTRL_BPS`
if [ "$BROADCAST_STORM_BPS" == "" ]; then
	BROADCAST_STORM_BPS=3036
fi

num=0
while [ "$num" -lt 5 ]
do
	BROADCAST_STORM_PORT_ENABLE=`nvram get 'x_BCSTORM_PORT'$num'_ENABLE'`
	if [ "$BROADCAST_STORM_ENABLE" == '1' ] && [ "$BROADCAST_STORM_PORT_ENABLE" == '1' ]; then
		echo $num 1 $BROADCAST_STORM_BPS 1 > /proc/StormCtrl
	else
		echo $num 0 0 1 > /proc/StormCtrl
	fi
	num=`expr $num + 1`
done

