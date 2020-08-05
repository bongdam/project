include $(DIR_USERS)/.config
include $(DIR_LINUX)/.config

scripts-files=$(filter-out startup.sh,$(wildcard *.sh))
all :
	echo "script"

romfs :
ifeq ($(CONFIG_RTL_NFJROM_MP),y)
	cp mp*.sh $(DIR_ROMFS)/bin/
else
	@cp $(scripts-files) $(DIR_ROMFS)/bin/
	@mv $(DIR_ROMFS)/bin/probe.sh $(DIR_ROMFS)/bin/startup.sh
endif
	@cp ../script_dbg/* $(DIR_ROMFS)/bin/
ifeq ($(CONFIG_APP_WSC),y)
	$(ROMFSINST) simplecfgservice.xml /etc/simplecfgservice.xml
	$(ROMFSINST) -s /var/wps /etc/simplecfg
endif
