CFLAGS += -Wall -O2 -fomit-frame-pointer
LDFLAGS +=
TARGET = aes-cbc
OBJS := main.o gio.o aes.o rndl.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

clean:
	rm -f $(OBJS) $(TARGET) $(OBJS:%.o=.%.depend)

install:
	:

%.o: .%.depend
.%.depend: %.c
	$(CC) $(CFLAGS_$*) $(CFLAGS) -M $< > $@
	@echo -en "\t" >> $@
	@echo '$(CC) $(CFLAGS_$*) $(CFLAGS) -c $*.c -o $*.o' >> $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif

.PHONY: all clean install
