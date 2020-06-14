# Light Quick makefile

LDFLAGS = 
INCLUDES = -I./include

.PHONY: default build clean tests headers

files = src/main.c src/lq.c src/lib/diet.c src/lib/marshall.c

OBJS = $(files:.c=.o)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $@

build: $(OBJS)
	$(CC) $(INCLUDES) -o target/lq $(OBJS) $(LDFLAGS)

clean:
	$(RM) src/*.o src/lib/*.o  target/lq

depend: $(SRCS)
	makedepend $(INCLUDES) $^