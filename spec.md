# The task

Write an extension to the linux firewall which makes it possible to specify which programs are allowed use which outgoing port.

More precisely, you should write a _user space program_ and a _kernel module_

## Firewall rules

A firewall rule consists of a port number and a filename (the full path) of a program separated by a space, meaning that the corresponding program is allowed to make outgoing connections on this TCP-port.

- If there is no rule for a given port, any program should be allowed to make outgoing connections on this port.
- A connection is not allowed when rules for the port exist, but the program trying to establish the connection is not in the list of allowed programs.
- If a connection is not allowed, it should be immediately terminated.

The kernel module processes the packets and maintains the firewall rules, and displays the firewall rules via printk  in __/var/log/kern.log__ . The output should be:  

>Firewall __rule:port program__

## Firewall __rule port program__

- For every rule that is configured, __port__ is the port number in decimal representation and __program__ is the full path to the executeable.
- When the kernel module is unloaded, the firewall extensions should be deleted.

## User space configuration

The user space program, which must be called firewallSetup, has commands firstly for triggering the listing of the firewall rules in /var/log/kern.log, and secondly for setting the firewall rules.
A new set of firewall rules overrides the old set (no appending).

- You should use the file/proc/firewallExtension for communication between the user program and the kernel.
- If replacing the set of firewall rules fails for any reason, the old set of firewall rules should be retained.

There should be two ways of calling the user
space program. The first one is:

>```shell
>firewallSetup  L
>```

- This way of calling the user space program causes the firewall rules
to be displayed in/var/log/kern.log as specified above.  


The second way of calling the program is:  

>```shell
>firewallSetup W filename
>```

* __filename__ is the name of the file containing the firewall rules. This file contains one firewall rule per line.
* firewallSetup should check whether the filename in the firewall rule denotes an existing executable file.
* If there is any error in the syntax or any filename is not an executable file, this program should abort with the message `ERROR: Ill-formed file`  and `ERROR: Cannot execute file` respectively.

## General Coding  

Your kernel code may assume that only well-formed files are written by firewallSetup.

- Only one process should be allowed to open the __/proc/firewallExtension__  file at any give time. If a second process tries to open this file it should receive the error message -EAGAIN.

- You need to ensure that you handle concurrency in the kernel correctly. In particular, any number of outgoing connections may be started at any time, hence several instances of the procedures handling the packets may be executed at the same time. It is very important that you maximize the degree of parallelism. In particular, your critical sections should be as short as possible.

- It is recommended to use the APIS for linked lists, locking and the Basic C Library functions provided by the kernel. Please be careful to check all buffer boundaries.
