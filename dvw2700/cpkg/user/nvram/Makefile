CFLAGS += -Os -fomit-frame-pointer -Wall
TARGET = libnvram.so
OBJS := rbtree.o nvram_user.o nvram_linux_r.o
OBJS_util := nvram_linux.o main.o

all: $(TARGET) nvram

$(TARGET): $(OBJS)
	$(CC) -shared -Wl,-soname,$(TARGET) -o $(TARGET) $(OBJS)

nvram: $(OBJS_util)
	$(CC) $(CFLAGS) -o $@ $^ -L. -lnvram -L$(SRCBASE)/libytool -lytool

clean:
	@rm -f $(TARGET) nvram $(OBJS) $(OBJS_util)

install: all
	install -d $(INSTALLDIR)/usr/lib
	install -m 755 $(TARGET) $(INSTALLDIR)/usr/lib
	$(STRIP) $(INSTALLDIR)/usr/lib/$(TARGET)
	install -d $(INSTALLDIR)/usr/sbin
	install nvram $(INSTALLDIR)/usr/sbin/nvram
	$(STRIP) $(INSTALLDIR)/usr/sbin/nvram

%.o: %.c
	$(if $(findstring $(patsubst %.c,%.o,$(<F)), $(OBJS)), \
	$(CC) -fPIC $(CFLAGS) -o $@ -c $<, \
	$(CC) $(CFLAGS) -o $@ -c $<)
