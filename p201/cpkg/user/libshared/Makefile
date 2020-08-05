CFLAGS += -fpic -Os -fomit-frame-pointer -Wall
TARGET = libshared.so
OBJS := $(patsubst %.c,%.o,$(wildcard *.c))
CFLAGS_nmpipe += -Wno-maybe-uninitialized

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -shared -Wl,-soname,$(TARGET) -o $(TARGET) $(OBJS)

clean:
	@rm -f $(TARGET) $(OBJS) $(OBJS:%.o=.%.depend)

install: all
	$(if $(STAGING_DIR),mkdir -p $(STAGING_DIR)/include && cp -u $(wildcard *.h) $(STAGING_DIR)/include)
	@install -d $(INSTALLDIR)/lib
	@install -m 755 $(TARGET) $(INSTALLDIR)/lib

%.o: .%.depend
.%.depend: %.c
	@$(CC) $(CFLAGS) -M $< > $@
	@echo -en "\t" >> $@
	@echo $(CC) $(CFLAGS_$*) $(CFLAGS) -c $*.c -o $*.o >> $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif

.PHONY: all clean all
