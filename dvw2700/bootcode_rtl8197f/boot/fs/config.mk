LOCAL_DIR  := $(ROOTDIR)/fs

LOCAL_SRCS := ff.c diskio.c
LOCAL_SRCS := $(addprefix $(LOCAL_DIR)/,$(LOCAL_SRCS))

LOCAL_HEADERS := ffconf.h ff.h integer.h diskio.h
LOCAL_HEADERS := $(addprefix $(LOCAL_DIR)/,$(LOCAL_HEADERS))

LOCAL_OBJS := $(LOCAL_SRCS:.c=.o)
$(LOCAL_OBJS): INCLUDES := -I./fs -I./sdcard -I./monitor
$(LOCAL_OBJS): %.o: %.c $(LOCAL_HEADERS)

ROM_OBJS += $(LOCAL_OBJS)
