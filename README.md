#### Memory checking
- To check for memory leaks (__which the kernel does not detect automatically__), I have used ___kedr___
- kedr is an analysys tool that checks memory at run time
    - You can find it on [github/euspecter/kedr](https://github.com/euspecter/kedr)
    - It __does not__ require recompiling the kernel
    - But it __does__ require compiling from source because its features are kernel specific
