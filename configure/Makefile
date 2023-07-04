CC = gcc
CFLAGS = -Wall -Wextra -I.

LIBS = -lsqlite3

SRCS = configure.c
OBJS = $(SRCS:.c=.o)

configure: $(OBJS)
	@$(CC) $(CFLAGS) $(OBJS) $(LIBS) -o configure

%.o: %.c
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@rm -f configure $(OBJS)
