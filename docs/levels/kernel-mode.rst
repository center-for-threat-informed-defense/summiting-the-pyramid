.. _Kernel-Mode:

---------------------
Column K: Kernel-Mode
---------------------

**Description**: Interfacing directly with ring 0 in the OS. Observables are in kernel mode.

As defined by Microsoft, the kernel, “implements the core functionality that everything else in the operating system depends upon.” [#f1]_ This is the heart of the 
Operating System, as it provides the services for everything, including managing threads, conflicts and errors, and memory space [#f2]_. Some of the kernel library 
support routines available start with ``Ke`` within the Windows Operating System. Defenders can monitor kernel activity through observables including registry 
modification, some event IDs, and network protocols. 


Kernel is the last level of the Operating System until you get to changing tactics to tampering with the hardware of the computer. If an adversary can access 
calls to these routines, they can bypass every other documented layer and blend in with the other kernel threads and routines occurring. However, the higher 
the adversaries climb up the levels, the harder they fall. Directly interfacing with the kernel has a greater possibility of breaking the operating system 
since everything is managed and run in a particular way. This is also the hardest level for a defender to detect. Context and monitoring abnormal processes 
can assist in identifying potential malicious activity. Overall, kernel behavior showcases the most robust fields to an analytic, since this will be the most 
difficult to evade.

Observables
^^^^^^^^^^^
+-------------------------------+-----------------------------------------------------------------------------------------+
| Category                      | Observable Fields                                                                       |
+===============================+=========================================================================================+
| Process                       | | Event ID 4688 (Process creation)                                                      |
|                               | | Event ID 4689 (Process exited)                                                        |
|                               | | Sysmon ID 8 (Create remote thread)                                                    |
+-------------------------------+-----------------------------------------------------------------------------------------+
| File                          | | Event ID 4663 (Attempt was made to access object)                                     |
+-------------------------------+-----------------------------------------------------------------------------------------+
| Registry Keys                 | | Event ID 4656 (Handle to object requested)                                            |
|                               | | Sysmon ID 12 (Registry object added/deleted)                                          |
|                               | | Event ID 4660 (Object deleted)                                                        |
|                               | | Event ID 4657 (Registry value modified)                                               |
+-------------------------------+-----------------------------------------------------------------------------------------+

.. rubric:: References

.. [#f1] https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/windows-kernel-mode-kernel-library
.. [#f2] https://www.techtarget.com/searchdatacenter/definition/kernel