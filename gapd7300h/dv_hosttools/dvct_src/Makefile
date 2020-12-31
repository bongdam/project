LDFLAGS += -lcrypto
CFLAGS += -Wall -Werror

all: dvct

OBJS = dvct.o

dvct: $(OBJS)
	gcc -o dvct $(OBJS) $(LDFLAGS)
	cp dvct ..
	#cp dvct dvct_unroll

clean: 
	rm -f $(OBJS) dvct dvct_unroll
