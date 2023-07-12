TARGET1 = ../src/glade.c
SOURCE1 = glade.xml
TARGET2 = ../src/css.c
SOURCE2 = css.xml
GLIB_COMPILE_RESOURCES = glib-compile-resources

all: $(TARGET1) $(TARGET2)

$(TARGET1): $(SOURCE1)
	$(GLIB_COMPILE_RESOURCES) --target=$@ --generate-source $<

$(TARGET2): $(SOURCE2)
	$(GLIB_COMPILE_RESOURCES) --target=$@ --generate-source $<

clean:
	rm -f $(TARGET1) $(TARGET2)

