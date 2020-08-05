CFLAGS += -g -O2 -fomit-frame-pointer -Wall
CFLAGS += -I$(DIR_LINUX)/include/net/rtl -include $(DIR_LINUX)/include/generated/autoconf.h

TARGET = aclwrite
OBJS := aclwrite.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

clean:
	rm -f $(OBJS) $(TARGET) $(OBJS:%.o=.%.depend)

install:
	install -d $(INSTALLDIR)/bin
	install $(TARGET) $(INSTALLDIR)/bin

%.o: .%.depend
.%.depend: %.c
	$(CC) $(CFLAGS_$*) $(CFLAGS) -M $< > $@
	@echo -en "\t" >> $@
	@echo $(CC) $(CFLAGS_$*) $(CFLAGS) -c $< -o $*.o >> $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif

.PHONY: all clean install
