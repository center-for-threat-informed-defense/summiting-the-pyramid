------------------------------------------------
Level 1: Operational and Environmental Variables
------------------------------------------------

**Description**: Variables which are constantly changing due to running processes, applications, and users. These observables provide a snapshot in time.

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
| Other                         |  | Pipe names                     |                              |
+-------------------------------+-----------------------------------+------------------------------+

