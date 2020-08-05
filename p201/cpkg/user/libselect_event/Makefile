CFLAGS += -fpic -Os -fomit-frame-pointer -Wall
TARGET = libselect_event.so
OBJS := $(patsubst %.c,%.o,$(wildcard *.c))

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -shared -Wl,-soname,$(TARGET) -o $(TARGET) $(OBJS)

clean:
	@rm -f $(TARGET) $(OBJS) $(OBJS:%.o=.%.depend)

install: all
	$(if $(STAGING_DIR),mkdir -p $(STAGING_DIR)/include && cp -u $(wildcard *.h) $(STAGING_DIR)/include)
	install -d $(INSTALLDIR)/lib
	install -m 755 $(TARGET) $(INSTALLDIR)/lib

%.o: .%.depend
.%.depend: %.c
	@$(CC) $(CFLAGS) -M $< > $@
	@echo -n -e "\t" >> $@
	@echo '$(CC) $(CFLAGS) -c $< -o $*.o' >> $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif
