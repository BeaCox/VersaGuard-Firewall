obj-m := VersaGuard_core.o 

ccflags-y := -std=gnu99 -Wno-declaration-after-statement

BIN_DIR := bin

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	@mkdir -p build 
	@mkdir -p $(BIN_DIR) 
	@mv -f *.o *.mod.c *.mod *.symvers *.order ./.??* build
	@mv -f *.ko $(BIN_DIR)

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

	@rm -rf $(BIN_DIR)
	@rm -rf build
