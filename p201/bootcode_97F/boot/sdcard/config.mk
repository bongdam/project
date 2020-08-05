LOCAL_DIR  := $(ROOTDIR)/sdcard

LOCAL_SRCS := sdcard.c
LOCAL_SRCS := $(addprefix $(LOCAL_DIR)/,$(LOCAL_SRCS))

LOCAL_HEADERS := sdcard.h
LOCAL_HEADERS := $(addprefix $(LOCAL_DIR)/,$(LOCAL_HEADERS))

LOCAL_OBJS := $(LOCAL_SRCS:.c=.o)
$(LOCAL_OBJS): INCLUDES := -I./sdcard/include -I./sdcard/arch/include -I./sdcard/arch/mips/include -I./sdcard/arch/arm -I./fs -I./monitor
$(LOCAL_OBJS): %.o: %.c $(LOCAL_HEADERS)

ROM_OBJS += $(LOCAL_OBJS)
