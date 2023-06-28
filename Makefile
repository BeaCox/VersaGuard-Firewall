CC = gcc
CFLAGS = -Iinclude `pkg-config --cflags gtk+-3.0`
LIBS = `pkg-config --libs gtk+-3.0` -export-dynamic -lsqlite3
BUILD_DIR = build

# 指定源文件和头文件
SOURCES = src/main.c src/database.c src/headerbar.c src/core_func.c
HEADERS = include/database.h include/headerbar.h include/core_func.h

# 生成目标文件的规则
OBJECTS = $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(SOURCES))

# 生成可执行文件的规则
app: $(OBJECTS)
	$(CC) -o $(BUILD_DIR)/app $(OBJECTS) $(LIBS)

# 生成目标文件的规则
$(BUILD_DIR)/%.o: src/%.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(BUILD_DIR)/app $(OBJECTS)

