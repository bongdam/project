#!/bin/sh

exec 3> /var/boa.conf
oper=$(nvram get OP_MODE)
if [ ${oper:-0} -eq 0 ]; then
	echo "Port 80" >&3
else
	sin_port=$(nvram get webacl_port)
	echo "Port ${sin_port:-8787}" >&3
fi

sin_addr=$(nvram get IP_ADDR)
echo "Listen ${sin_addr:-192.168.200.254}" >&3
while read -r LINE; do
	[ -n "${LINE}" -a "${LINE:0:1}" != "#" -a "${LINE:0:4}" != "Port" -a "${LINE:0:6}" != "Listen" ] && {
		echo ${LINE} >&3
	}
done < /etc/boa/boa.conf
exec 3>&-

boa -f /var/boa.conf
