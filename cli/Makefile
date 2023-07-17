CC = gcc
CFLAGS = -Wall -Wextra -Iinclude $(shell pkg-config --cflags glib-2.0)

LIBS = -lsqlite3 $(shell pkg-config --libs glib-2.0)

SRCDIR = src
OBJDIR = build
BINDIR = bin

SRCS = $(wildcard $(SRCDIR)/*.c)
OBJS = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SRCS))
EXEC = VersaGuard-cli

$(EXEC): $(OBJS)
	@$(CC) $(CFLAGS) $(OBJS) $(LIBS) -o $(EXEC)
	@mkdir -p $(BINDIR)
	@mv $(EXEC) $(BINDIR)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@rm -rf $(OBJDIR) $(BINDIR) $(EXEC)

.PHONY: clean
