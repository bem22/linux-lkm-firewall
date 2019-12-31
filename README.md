## Character Firewall Extension - LKM (loadable kernel module)
> This is an LKM that implements firewall extension for linux kernel

### __WARNING__
>Although this LKM has been tested, I do not recommend loading it on your own machine and I do not give any guarantee that it will not crash your kernel or alter the memory on your machine.

#### Features
- Custom linked list to store rules
- Does not leak memory on rmmod

#### Implementation

#### Testing
There are several tests I wrote for this to ensure all the features listed above

#### Memory checking
- To check for memory leaks (__which the kernel does not detect automatically__), I have used ___kedr___
    > kedr is an analysys tool that checks memory at run time
- You can find it on [github/euspecter/kedr](https://github.com/euspecter/kedr)
- It __does not__ require recompiling the kernel
- But it __does__ require compiling from source because its features are kernel specific

## License
This project is licensed under the Apache License Version 2.0 - see the [LICENSE.md](LICENSE.md) file for details

## Built with
- [Make](https://www.gnu.org/software/make/manual/make.html) - GNU Make
- [CLion](https://www.jetbrains.com/clion/) - IDEA Project
- [valgrind](https://valgrind.org/) - memory testing

## Authors
- bem22 
