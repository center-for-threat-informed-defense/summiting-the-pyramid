------------------------------------------------
Level 1: Operational and Environmental Variables
------------------------------------------------

**Description**: Variables which are constantly changing due to running processes, applications, and users. These observables provide a snapshot in time.

**Examples**: Hash values, IP addresses, protocol-specific ports, file names, domain names, processes, user oriented observables, others

Observables
^^^^^^^^^^^
+-------------------------------+---------------------------------+------------------------------+
| Category                      | Observable Fields               |   Observable Values          |
+===============================+=================================+==============================+
| Protocol-specific ports       |  | dest_port (CAR)              |                              |
|                               |  | src_port (CAR)               |                              |
+-------------------------------+---------------------------------+------------------------------+
| Filenames                     |  | Image (Sysmon)               |                              |
|                               |  | Parent image (Sysmon)        |                              |
|                               |  | Current directory (Sysmon)   |                              |
|                               |  | Extension (Sysmon)           |                              |
|                               |  | Filepath (CAR)               |                              |
|                               |  | image_path (CAR)             |                              |
+-------------------------------+---------------------------------+------------------------------+
| Domain names                  |  | fqdn (CAR)                   |                              |
|                               |  | ad_domain (CAR)              |                              |
|                               |  | target_ad_domain (CAR)       |                              |
+-------------------------------+---------------------------------+------------------------------+

