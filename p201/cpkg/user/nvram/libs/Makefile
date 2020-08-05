FIXED_KEY := 1
STORE_BIN2MTD := 1

CFLAGS += -fpic -Os -Wall -Wno-unused-result -Isecurity -DMINILZO_CFG_SKIP_LZO_UTIL -D_NDEBUG
CFLAGS += -DFIXED_KEY=$(FIXED_KEY) -DSTORE_BIN2MTD=$(STORE_BIN2MTD)
TARGET = libnvram.so
OBJS := crypto_linux.o minilzo.o nvram_store.o nvram_lib.o
ifneq ($(FIXED_KEY),1)
OBJS += file_utils.o kst.o ktkst.o
endif

vpath %.c security

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -shared -Wl,-soname,$(TARGET) -o $(TARGET) $(OBJS)

clean:
	@rm -f $(OBJS) $(TARGET) $(OBJS:%.o=.%.depend)

install: all
	install -d $(INSTALLDIR)/lib
	install -m 755 $(TARGET) $(INSTALLDIR)/lib

%.o: .%.depend
.%.depend: %.c
	@$(CC) $(CFLAGS_$*) $(CFLAGS) -M $< > $@
	@/bin/echo -en "\t" >> $@
	@/bin/echo $(CC) $(CFLAGS_$*) $(CFLAGS) -c $< -o $*.o >> $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif

.PHONY: all clean install
