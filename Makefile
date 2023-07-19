
CC ?= cc

override CFLAGS := -fsanitize=address -Wstringop-overflow=0 -Wall -Wextra -O2 -ggdb3 $(CFLAGS)
override LDLIBS += -lpthread

gwstms: gwstms.c

clean:
	rm -f gwstms
