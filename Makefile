# 顶层Makefile

SUBDIRS = core cli gui

.PHONY: all clean

all:
	for dir in $(SUBDIRS); do \
	   $(MAKE) -C $$dir; \
	done

clean:
	for dir in $(SUBDIRS); do \
	   $(MAKE) -C $$dir clean; \
	done
