KERNEL=/lib/modules/`uname -r`/build
#ARCH=i386
#KERNEL=/usr/src/kernels/`uname -r`-i686

MODULE = firewallExtension.ko
 
obj-m += firewallExtension.o

all: $(MODULE)

firewallExtension.ko: firewallExtension.c firewallExtension.h
	make -C  $(KERNEL) M=$(PWD) modules

clean:
	make -C $(KERNEL) M=$(PWD) clean

install:	
	make -C $(KERNEL) M=$(PWD) modules_install

quickInstall:
	cp $(MODULE) /lib/modules/`uname -r`/extra
