TARGET = ../src/glade.c
SOURCE = glade.xml

$(TARGET): $(SOURCE)
	glib-compile-resources --target=$(TARGET) --generate-source $(SOURCE)
	
clean:
	rm -rf $(TARGET)
