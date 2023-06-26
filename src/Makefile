CC = gcc
CFLAGS = `pkg-config --cflags gtk+-3.0`
LIBS = `pkg-config --libs gtk+-3.0` -export-dynamic -lsqlite3

app: main.o
	$(CC) -o app main.o $(LIBS)

main.o: main.c
	$(CC) $(CFLAGS) -c main.c

clean:
	rm -f app main.o

