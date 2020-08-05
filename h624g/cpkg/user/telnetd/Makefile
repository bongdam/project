CFLAGS += -g -O2 -fomit-frame-pointer -Wall
LDFLAGS = -L$(SRCBASE)/libytool -lytool
LDFLAGS += -L$(SRCBASE)/nvram -lnvram -lcrypt

TARGET = telnetd
OBJS := telnetd.o tlogin.o bbwrap.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)
	$(STRIP) --strip-all $@

clean:
	rm -f $(OBJS) $(TARGET) $(OBJS:%.o=.%.depend)

install:
	$(ROMFSINST) /bin/$(TARGET)

%.o: .%.depend
.%.depend: %.c
	$(CC) $(CFLAGS) -M $< > $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif
