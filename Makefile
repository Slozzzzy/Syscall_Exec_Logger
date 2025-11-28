obj-m += exec_kprobe.o
exec_kprobe-objs := exec_kprobe_core.o exec_kprobe_nonlogic.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
