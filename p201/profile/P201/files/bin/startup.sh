#!/bin/sh
flash probe
if [ ! -e "$SET_TIME" ]; then
	flash settime
fi
eval `flash get HW_WSC_PIN`
if [ "$HW_WSC_PIN" = "" ]; then
	flash gen-pin
fi
