.. _User-Mode:

-------------------
Column U: User-Mode
-------------------

**Description**: Observables associated with user-mode OS activity.

User-mode calls occur where user-mode applications executed in CPU Ring 3 pass control to the kernel-mode functions executed in CPU Ring 0 with privileged access. 
The user-mode application has little visibility and control to what happens at this level. This includes kernel-drivers and functions that call upon the kernel 
directly to complete tasks. These system calls are usually implemented by storing values in system registers to indicate which functionality is requested, 
followed by an interrupt signal in assembly. These low-level actions are usually performed by C wrapper functions. In Windows, these system call C wrapper 
functions usually start with Nt or Zw [#f1]_. In other operating systems, these C wrapper functions are usually included in libc. However, these wrapper function 
can be bypassed in user-mode by directly setting the appropriate register(s) and invoking the direct system call interrupt. User-mode calls can also include the 
actions resulting from routines, such as file manipulation or communication protection.

User-mode provides a layer of separation between the user and the kernel. However, user-mode observables could potentially be bypassed by the adversary directly interfacing with the kernel, avoiding triggering user-mode observables.

Observables
^^^^^^^^^^^
+-------------------------------+-----------------------------------+--------------------------------------------+
| Category                      | Observable Fields                 |   Observable Values                        |
+===============================+===================================+============================================+
| Process API Calls             |  | create (CAR)                   | | Sysmon ID 1 (Process creation)           |
|                               |                                   | | Sysmon ID 5 (Process termination)        |
|                               |                                   | | Sysmon ID 10 (Process access)            |
+-------------------------------+-----------------------------------+--------------------------------------------+
| File API Calls                |                                   | | Sysmon ID 2 (File creation time changed) |
|                               |                                   | | Sysmon ID 11 (File create)               |
|                               |                                   | | Sysmon ID 15 (File create stream hash)   |
|                               |                                   | | Sysmon ID 23 (File deletion)             |
+-------------------------------+-----------------------------------+--------------------------------------------+
| Driver API Calls              |                                   | | Sysmon ID 6 (Driver loaded)              |
+-------------------------------+-----------------------------------+--------------------------------------------+
| Registry Key API Calls        |                                   | | Sysmon ID 13 (Registry value set)        |
|                               |                                   | | Sysmon ID 14 (Registry object renamed)   |
+-------------------------------+-----------------------------------+--------------------------------------------+

.. rubric:: References

.. [#f1] https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-nt-and-zw-versions-of-the-native-system-services-routines