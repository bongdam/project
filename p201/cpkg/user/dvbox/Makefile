include $(DIR_ROOT)/.config

CFLAGS += -s -O2 -fomit-frame-pointer -Wall
LDFLAGS += -L$(STAGING_DIR)/lib -lnvram -lshared -lytool

TARGET = dvbox
OBJS := main.o md.o dvflag.o gpio.o preq.o chpwd.o phyconfig.o
ifneq ($(CONFIG_BZBOX_busybox-1.13),y)
OBJS += vconfig_busybox-1.13.o
endif

all: flagnames $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

clean:
	rm -f $(OBJS) $(TARGET) $(OBJS:%.o=.%.depend)

install:
	install -m 755 $(TARGET) $(INSTALLDIR)/bin
	$(STRIP) $(INSTALLDIR)/bin/$(TARGET)
	@for i in $(shell $(CROSS_COMPILE)nm $(TARGET) | grep __applet_entry__ | sed 's/.*__applet_entry__//'); do \
		ln -sf $(TARGET) $(INSTALLDIR)/bin/$$i; \
	done

flagnames:
	@cat $(STAGING_DIR)/include/dvflag.h | grep '<<' | grep -oP "^\s*#\s*define\s+DF_\w+" | awk '!/DF_ADMIN_EN/{ print "{ "$$2", \""substr($$2,4)"\" }," }' > .$@.tmp
	@if diff .$@.tmp $@.c >/dev/null 2>&1; then \
		rm .$@.tmp; \
	else \
		mv .$@.tmp $@.c; \
	fi

dvflag.c: flagnames ;

%.o: .%.depend
.%.depend: %.c
	@$(CC) $(CFLAGS) -M $< > $@
	@echo -en "\t" >> $@
	@echo $(CC) $(CFLAGS_$*) $(CFLAGS) -c $*.c -o $*.o >> $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif

.PHONY: all clean install flagnames
