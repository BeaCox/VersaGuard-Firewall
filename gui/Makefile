CC = gcc
CFLAGS = -Iinclude `pkg-config --cflags gtk+-3.0`
LIBS = `pkg-config --libs gtk+-3.0` -export-dynamic -lsqlite3
BUILD_DIR = build
BIN_DIR = bin

# 指定源文件和头文件
SOURCES = src/main.c src/database.c src/headerbar.c src/core_func.c src/utils.c src/logs.c src/glade.c src/img.c src/css.c
HEADERS = include/global.h include/database.h include/headerbar.h include/core_func.h include/utils.h include/logs.h

# 生成目标文件和资源文件的规则
OBJECTS = $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(SOURCES))
GLADE_TARGET = src/glade.c
GLADE_SOURCE = ui/glade.xml
CSS_TARGET = src/css.c
CSS_SOURCE = ui/css.xml
IMG_TARGET = src/img.c
IMG_SOURCE = ui/img.xml

.PHONY: all clean

all: $(BIN_DIR)/VersaGuard-gui $(GLADE_TARGET) $(CSS_TARGET) $(IMG_TARGET)

$(BIN_DIR)/VersaGuard-gui: $(OBJECTS)
	@mkdir -p $(BIN_DIR)
	$(CC) -o $(BIN_DIR)/VersaGuard-gui $(OBJECTS) $(LIBS)

$(BUILD_DIR)/%.o: src/%.c $(HEADERS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(GLADE_TARGET):
	$(MAKE) -C ui

$(CSS_TARGET):
	$(MAKE) -C ui

$(IMG_TARGET):
	$(MAKE) -C img

clean:
	rm -rf $(BIN_DIR)
	rm -rf $(BUILD_DIR)
	$(MAKE) -C ui clean
	$(MAKE) -C img clean


