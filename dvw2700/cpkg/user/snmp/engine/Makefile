.SUFFIXES : .c .o

C_FLAGS += -Wall -c -Os -fomit-frame-pointer

CFLAGS += $(C_FLAGS)
CFLAGS += -I../lib
CFLAGS += $(DV_FLAGS)

PROC_OBJ = $(patsubst %.c, %.o, $(wildcard *.c))

all: $(PROC_OBJ)

clean:
	rm -f $(PROC_OBJ)
