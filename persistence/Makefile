obj-m += mw.o
mw-objs += sensitive.o main.o
KDIR = /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(shell pwd) EXTRA_CFLAGS="${OPTS}" modules
