.. _Ephemeral Values:

-------------------------
Level 1: Ephemeral Values
-------------------------

**Description**: Observables that are trivial for an adversary to change, or that change even without adversary intervention.

Ephemeral values capture the context of what is currently happening to a user, process, or system. These observables include process IDs, hash values, domain names, filenames, and others. While these observables offer high  :ref:`precision <Precision>`, they are often easy to evade.

**Why are these observables the lowest level?**

These observables cannot be relied on to identify adversary behavior. These indicators take minimal effort for an adversary to change [#f1]_. A new hash value can be created if one bit is changed in a file. A filename can be obfuscated within an image. When building out analytics, these observables will mostly capture values that point to the context of a certain application, user, or process. While these observables can detect known malicious applications or processes, they will not detect anything new, nor will they detect if the adversary decides to change an operational or environmental variable to evade detection. To ensure detection in-depth, these observables should be combined with observables from other levels.

**Examples**: Hash values, IP addresses, protocol-specific ports, file names, domain
names, processes, user oriented observables, others

Observables
^^^^^^^^^^^
+-------------------------------+-----------------------------------+--------------------------------+--------------------------------+
| Category                      | Observables                       |   Generating Activity          | Evade Behavior                 |
+===============================+===================================+================================+================================+
| Hash Values                   |  | Hashes (Sysmon)                | Passing a file or object       | Change one bit in a file and   |
|                               |                                   | through a mathmatical formula  | regenerate the hash.           |
|                               |                                   | to create a unique identifying |                                |
|                               |                                   | number.                        |                                |
+-------------------------------+-----------------------------------+--------------------------------+--------------------------------+
| IP Address                    |  | SourceIp (Sysmon)              | Assigned by ISP. [#f2]_        | Connect to a different ISP,    |
|                               |  | DestinationIp (Sysmon)         |                                | restart the router or modem, or|
|                               |                                   |                                | utilize a VPN.                 |
+-------------------------------+-----------------------------------+--------------------------------+--------------------------------+
| Protocol-Specific Ports       |  | DestinationPort (Sysmon)       | Ports are standardized across  | Change port configuration      |
|                               |  | SourcePort (Sysmon)            | network devices, [#f3]_ while  | settings in the code or        |
|                               |                                   | others aren't associated       | computer.                      |
|                               |                                   | with a protocol standard.      |                                |
+-------------------------------+-----------------------------------+--------------------------------+--------------------------------+
| Filenames                     |  | Image (Sysmon)                 | Created by the user to identify| Filename can be changed by the |
|                               |  | Parent image (Sysmon)          | a file.                        | user or can be obfuscated in   |
|                               |  | CurrentDirectory (Sysmon)      |                                | code deployment.               |
|                               |  | Extension (Sysmon)             |                                |                                |
|                               |  | TargetFilename (Sysmon)        |                                |                                |
+-------------------------------+-----------------------------------+--------------------------------+--------------------------------+
| Domain Names                  |  | SourceHostname (Sysmon)        | Reigster the domain name with  | Map tools or website           |
|                               |  | DestinationHostname (Sysmon)   | the registrar. [#f4]_          | to a different domain name.    |
+-------------------------------+-----------------------------------+--------------------------------+--------------------------------+
| Processes                     |  | ProcessGuid (Sysmon)           | New processes create a child   | Operating System Kernel creates|
|                               |  | ProcessId (Sysmon)             | process. The parent and child  | a new process and associated   |
|                               |  | Parent process GUID (Sysmon)   | processes are each assigned a  | metadata.                      |
|                               |  | Subject SID (EID)              | PID. [#f5]_                    |                                |
|                               |  | Target SID (EID)               |                                |                                |
|                               |  | New Process ID (EID)           |                                |                                |
|                               |  | Creator Process ID (WEID)      |                                |                                |
+-------------------------------+-----------------------------------+--------------------------------+--------------------------------+
| Pipes                         |  | Pipe Names (Sysmon)            | A pipe server or user specifies| Change the name of the pipe.   |
|                               |                                   | a name for a pipe when it calls|                                |
|                               |                                   | CreateNamedPipe functon. [#f6]_|                                |
+-------------------------------+-----------------------------------+--------------------------------+--------------------------------+

.. rubric:: References

.. [#f1] http://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html
.. [#f2] https://usa.kaspersky.com/resource-center/definitions/what-is-an-ip-address
.. [#f3] https://www.cloudflare.com/learning/network-layer/what-is-a-computer-port/
.. [#f4] https://www.codecademy.com/resources/blog/what-is-a-domain-name/#domain-name-registrars-and-registries
.. [#f5] https://www.tutorialspoint.com/inter_process_communication/inter_process_communication_process_creation_termination.htm
.. [#f6] https://learn.microsoft.com/en-us/windows/win32/ipc/pipe-names
