--------------------------
Level 7: Kernel/Interfaces
--------------------------

**Description**: Interfacing directly with ring 0 in the OS. Observables are in kernel mode.

**Examples**: Registry modification, event IDs, network protocol

Observables
^^^^^^^^^^^
+-------------------------------+-----------------------------------+-------------------------------------+
| Category                      | Observable Fields                 |   Observable Values                 |
+===============================+===================================+=====================================+
| API Calls                     | | add (CAR)                       | | Event ID 4688 (Process Creation)  |
|                               | | remove (CAR)                    | | Event ID 4689 (Process Exited)    |
|                               | | key_edit (CAR)                  | | Sysmon ID 8 (Create Remote Thread)|
|                               | | value_edit (CAR)                |                                     |
+-------------------------------+-----------------------------------+-------------------------------------+