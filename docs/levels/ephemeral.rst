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
+-------------------------------+-----------------------------------+------------------------------+
| Category                      | Observable Fields                 |   Observable Values          |
+===============================+===================================+==============================+
| Hash values                   |  | Hashes (Sysmon)                |                              |
|                               |  | md5_hash (CAR)                 |                              |
|                               |  | sha1_hash (CAR)                |                              |
|                               |  | sha256_hash (CAR)              |                              |
+-------------------------------+-----------------------------------+------------------------------+
| IP address                    |  | target_address (CAR)           |                              |
|                               |  | dest_ip (CAR)                  |                              |
|                               |  | src_ip (CAR)                   |                              |
+-------------------------------+-----------------------------------+------------------------------+
| Protocol-specific ports       |  | dest_port (CAR)                |                              |
|                               |  | src_port (CAR)                 |                              |
+-------------------------------+-----------------------------------+------------------------------+
| Filenames                     |  | Image (Sysmon)                 |                              |
|                               |  | Parent image (Sysmon)          |                              |
|                               |  | Current directory (Sysmon)     |                              |
|                               |  | Extension (Sysmon)             |                              |
|                               |  | Filepath (CAR)                 |                              |
|                               |  | image_path (CAR)               |                              |
|                               |  | Current Working Directory (CAR)|                              |
|                               |  | App name (CAR)                 |                              |
|                               |  | Auth target (CAR)              |                              |
+-------------------------------+-----------------------------------+------------------------------+
| Domain names                  |  | fqdn (CAR)                     |                              |
|                               |  | ad_domain (CAR)                |                              |
|                               |  | target_ad_domain (CAR)         |                              |
+-------------------------------+-----------------------------------+------------------------------+
| Processes                     |  | Process GUID (Sysmon)          |                              |
|                               |  | Process ID (Sysmon)            |                              |
|                               |  | Parent process GUID (Sysmon)   |                              |
|                               |  | Subject SID (EID)              |                              |
|                               |  | Target SID (EID)               |                              |
|                               |  | New process ID (EID)           |                              |
|                               |  | Creator Process ID (WEID)      |                              |
|                               |  | pid (CAR)                      |                              |
|                               |  | ppid (CAR)                     |                              |
+-------------------------------+-----------------------------------+------------------------------+
| Other                         |  | Pipe names (Sysmon)            |                              |
+-------------------------------+-----------------------------------+------------------------------+

.. rubric:: References

.. [#f1] http://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html