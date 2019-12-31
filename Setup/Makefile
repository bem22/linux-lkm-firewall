KERNELDIR=/lib/modules/`uname -r`/build
#ARCH=i386
#KERNELDIR=/usr/src/kernels/`uname -r`-i686

PROGRAMS = firewallSetup

all: $(PROGRAMS)

clean:
	rm firewallSetup

firwallSetup: firewallSetup.c firewallSetup.h
	gcc -Wall -Werror -o fireWallSetup