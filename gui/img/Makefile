TARGET = ../src/img.c
SOURCE = img.xml

$(TARGET): $(SOURCE)
	glib-compile-resources --target=$(TARGET) --generate-source $(SOURCE)
	
clean:
	rm -rf $(TARGET)
