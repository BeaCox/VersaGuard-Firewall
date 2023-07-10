CC = gcc
CFLAGS = -Wall -Wextra -Iinclude

LIBS = -lsqlite3

SRCDIR = src
OBJDIR = build

SRCS = $(wildcard $(SRCDIR)/*.c)
OBJS = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SRCS))
EXEC = configure

$(EXEC): $(OBJS)
	@$(CC) $(CFLAGS) $(OBJS) $(LIBS) -o $(EXEC)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@rm -rf $(OBJDIR) $(EXEC)

.PHONY: clean
