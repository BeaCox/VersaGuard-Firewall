SUBDIRS = core cli gui

.PHONY: all clean

all: 
	for dir in $(SUBDIRS); do \
	   $(MAKE) -C $$dir; \
	done
	@mkdir -p bin
	cp -f cli/bin/VersaGuard-cli bin/
	cp -f gui/bin/VersaGuard-gui bin/        
	cp -f core/bin/VersaGuard_core.ko bin/

clean:
	rm -rf bin
	for dir in $(SUBDIRS); do \
	   $(MAKE) -C $$dir clean; \
	done
