CFLAGS += -Wall
EXES := $(patsubst %.c,%,$(wildcard *.c))

all: $(EXES)

% : %.c
	$(CC) $(CFLAGS) -o $@ $< -L../ -lytool

clean:
	@rm -f $(OBJS) $(EXES)
