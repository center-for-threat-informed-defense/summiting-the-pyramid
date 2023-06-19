.. _System Calls:

---------------------
Level 6: System Calls
---------------------

**Description**: Transition from user mode to kernel mode.

System calls are where user-mode applications executed in CPU Ring 3 pass control to the kernel-mode functions executed in CPU Ring 0 with privileged access. 
The user-mode application has little visibility and control to what happens at this level. This includes kernel-drivers and functions that call upon the kernel 
directly to complete tasks. These system calls are usually implemented by storing values in system registers to indicate which functionality is requested, 
followed by an interrupt signal in assembly. These low-level actions are usually performed by C wrapper functions. In Windows, these system call C wrapper 
functions usually start with Nt or Zw [#f1]_. In other operating systems, these C wrapper functions are usually included in libc. However, these wrapper function 
can be bypassed in user-mode by directly setting the appropriate register(s) and invoking the direct system call interrupt. System calls also include the 
actions resulting from routines, such as file manipulation or communication protection.

**Why are System calls relevant for detections?**

System calls provide another level of abstraction for adversaries to utilize within their tools. If there are system calls that are available to use and do 
not trigger alerts or events within the operating system, it might be more appealing for an adversary to skip the previous levels and use system calls.
They could leverage open source collections of system calls from modern and older releases of Windows to see if any help accomplish their goals [#f2]_
Like the previous level, it might be more difficult for defenders to detect the use of system calls and true positives of malicious activity. The further 
up you go through this leveling, the more likely adversary behavior will be blended in with benign behavior. However, it does indicate that it is more 
difficult for an adversary to evade these system calls, as they will be directly interfacing with the operating system. 

**Examples**: File manipulation, communication protection

Observables
^^^^^^^^^^^
+-------------------------------+-----------------------------------+-------------------------------------------+
| Category                      | Observable Fields                 |   Observable Values                       |
+===============================+===================================+===========================================+
| Process API Calls             |  |                                | | Sysmon ID 10 (Process access)           |
+-------------------------------+-----------------------------------+-------------------------------------------+
| File API Calls                |  |                                | | Sysmon ID 11 (File create)              |
|                               |  |                                | | Sysmon ID 15 (File create stream hash)  |
|                               |  |                                | | Sysmon ID 23 (File deletion)            |
+-------------------------------+-----------------------------------+-------------------------------------------+
| Driver API Calls              |  |                                | | Sysmon ID 6 (Driver loaded)             |
+-------------------------------+-----------------------------------+-------------------------------------------+
| Registry Key API Calls        |  |                                | | Sysmon ID 13 (Registry value set)       |
|                               |  |                                | | Sysmon ID 14 (Registry object renamed)  |
+-------------------------------+-----------------------------------+-------------------------------------------+

.. rubric:: References

.. [#f1] https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-nt-and-zw-versions-of-the-native-system-services-routines
.. [#f2] https://github.com/j00ru/windows-syscalls 