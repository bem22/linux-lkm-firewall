## Linux Firewall Extension - LKM (loadable kernel module)
> This is an LKM that implements firewall extension for Linux kernel

### __WARNING__
>Although this LKM has been tested, I do not recommend loading it on your own machine and I do not give any guarantee that it will not crash your kernel or alter the memory on your machine.

#### Implementation
> It is implemented using the linked list defined in firewallExtension.h and it is using Linux semaphores to avoid concurrency conflicts between multiple processes that might access the module.

- Loading the module will create a process that will filter ip based on the current loaded rules
    - The userspace program is attributed with passing the rules from string to kernelspace memory
    - Once loaded, the string is parsed inside a linked list
- The firewall will try to match every outgoing packet to a port in the rules.
    - If no rule is specified ofr a port, then any application can freely use the port
    - If there is at least a rule, all application but the one specified are rejected

#### Testing
In the [own](own) folder there is a test file called `test.sh`. This will provide basic testing for loading rules into the lkm.

There is another bash script called firewallExtension that is used to test memory errors and leaks with [kedr](https://github.com/euspecter/kedr). Read more on the kedr page

#### Memory checking
- To check for memory leaks (__which the kernel does not detect automatically__), I have used ___kedr___
    > kedr is an analysis tool that checks memory at run time
- You can find it on [github/euspecter/kedr](https://github.com/euspecter/kedr)
- It __does not__ require recompiling the kernel
- But it __does__ require compiling from source because its features are kernel specific

## Efficiency
- Efficiency could be improved by linking all rules for a particular port instead of linking all rules for all ports in random order.
- For a very large number of rules, this filter becomes very slow.

## License
This project is licensed under the Apache License Version 2.0 - see the [LICENSE.md](LICENSE.md) file for details

## Built with
- [Make](https://www.gnu.org/software/make/manual/make.html) - GNU Make
- [CLion](https://www.jetbrains.com/clion/) - IDEA Project
- [kedr](https://github.com/euspecter/kedr) - Memory checking
