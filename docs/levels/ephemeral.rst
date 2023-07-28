.. _Ephemeral Values:

-------------------------
Level 1: Ephemeral Values
-------------------------

**Description**: Observables that are trivial for an adversary to change, or that change even without adversary intervention.

Ephemeral values capture the context of what is currently happening to a user, process, or system. This includes observables 
such as process IDs, hash values, domain names, file names, and others. While these observables provide context for an attack, they do little to 
outline the behaviors of both normal users and the adversary.

**Why are these observables the lowest level?**

These observables cannot be relied on to identify adversary behavior. These indicators take minimal effort for an adversary to change [#f1]_. A new hash value 
can be created if one bit is changed in a file. A file name can be obfuscated within an image. When building out analytics, these observables will mostly 
capture values which point to the context of a certain application, user, or process. While these observables can detect known malicious applications or 
processes, these will not detect anything new, or if the adversary decides to change an operational or environmental variable to evade detection. To 
ensure detection in-depth, these observables should be combined with other level observables.

**Examples**: Hash values, IP addresses, protocol-specific ports, file names, domain names, processes, user oriented observables, others

Observables
^^^^^^^^^^^
+-------------------------------+-----------------------------------+--------------------------------+--------------------------------+
| Category                      | Observables                       |   Generating Activity          | Evade Behavior                 |
+===============================+===================================+================================+================================+
| Hash values                   |  | Hashes (Sysmon)                | Passing file or object through | Change one bit in file and     |
|                               |                                   | mathmatical formula to create  | regenerate hash                |
|                               |                                   | unique identifying number      |                                |
|                               |                                   |                                |                                |
+-------------------------------+-----------------------------------+--------------------------------+--------------------------------+
| IP address                    |  | SourceIp (Sysmon)              | Assigned by ISP [#f2]_         | Connect to a different ISP,    |                  
|                               |  | DestinationIp (Sysmon)         |                                | restart router or modem, or    |
|                               |                                   |                                | utilize a VPN                  |
+-------------------------------+-----------------------------------+--------------------------------+--------------------------------+
| Protocol-specific ports       |  | DestinationPort (Sysmon)       | Ports are standardized across  | Change port configuration      |
|                               |  | SourcePort (Sysmon)            | network devices [#f3]_, while  | settings in code or computer   |
|                               |                                   | others aren't associated       |                                |
|                               |                                   | with a protocol standard       |                                |
+-------------------------------+-----------------------------------+--------------------------------+--------------------------------+
| Filenames                     |  | Image (Sysmon)                 | Created by user to identify    | Filename can be changed by user|
|                               |  | Parent image (Sysmon)          | file                           | or can be obfuscated in code   |
|                               |  | CurrentDirectory (Sysmon)      |                                | deployment                     |
|                               |  | Extension (Sysmon)             |                                |                                |
|                               |  | TargetFilename (Sysmon)        |                                |                                |
+-------------------------------+-----------------------------------+--------------------------------+--------------------------------+
| Domain names                  |  | SourceHostname (Sysmon)        | Reigster domain name with      | Map tools  or website          |
|                               |  | DestinationHostname (Sysmon)   | registrar [#f4]_               | to different domain name       |
+-------------------------------+-----------------------------------+--------------------------------+--------------------------------+
| Processes                     |  | ProcessGuid (Sysmon)           | New processes create           | Operating System Kernel creates|
|                               |  | ProcessId (Sysmon)             | creates a child process. The   | a new process and associated   |
|                               |  | Parent process GUID (Sysmon)   | parent and child processes each| metadata                       |
|                               |  | Subject SID (EID)              | are assigned a PID [#f5]_      |                                |
|                               |  | Target SID (EID)               |                                |                                |
|                               |  | New process ID (EID)           |                                |                                |
|                               |  | Creator Process ID (WEID)      |                                |                                |
+-------------------------------+-----------------------------------+--------------------------------+--------------------------------+
| Pipes                         |  | Pipe names (Sysmon)            | A pipe server or user specifies| Change the name of the pipe    |
|                               |                                   | a name for a pipe when it calls|                                |
|                               |                                   | CreateNamedPipe functon [#f6]  |                                |
+-------------------------------+-----------------------------------+--------------------------------+--------------------------------+

.. rubric:: References

.. [#f1] http://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html
.. [#f2] https://usa.kaspersky.com/resource-center/definitions/what-is-an-ip-address
.. [#f3] https://www.cloudflare.com/learning/network-layer/what-is-a-computer-port/
.. [#f4] https://www.codecademy.com/resources/blog/what-is-a-domain-name/#domain-name-registrars-and-registries
.. [#f5] https://www.tutorialspoint.com/inter_process_communication/inter_process_communication_process_creation_termination.htm
.. [#f6] https://learn.microsoft.com/en-us/windows/win32/ipc/pipe-names
