CC = gcc
CFLAGS = `pkg-config --cflags gtk+-3.0`
LIBS = `pkg-config --libs gtk+-3.0` -export-dynamic -lsqlite3
BUILD_DIR = ../build

app: main.o database.o
	$(CC) -o $(BUILD_DIR)/app $(BUILD_DIR)/main.o $(BUILD_DIR)/database.o $(LIBS)

main.o: main.c database.h
	$(CC) $(CFLAGS) -c main.c -o $(BUILD_DIR)/main.o

database.o: database.c database.h
	$(CC) $(CFLAGS) -c database.c -o $(BUILD_DIR)/database.o

clean:
	rm -f $(BUILD_DIR)/app $(BUILD_DIR)/main.o $(BUILD_DIR)/database.o

