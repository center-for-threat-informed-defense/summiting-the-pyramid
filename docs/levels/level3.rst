----------------------------------------
Level 3: Tools Outside Adversary Control
----------------------------------------

**Description**: Tools which are managed by outside organizations. The adversary has minimal control in changing functions and protocols to make them specific for their attack.

**Examples**: Signatures, command-line arguments, tool-specific configurations, metadata, binaries

Observables
^^^^^^^^^^^
+-------------------------------+-----------------------------------+------------------------------+
| Category                      | Observable Fields                 |   Observable Values          |
+===============================+===================================+==============================+
| Command-line arguments        |  | Command line (Sysmon, CAR)     |                              |
|                               |  | Process Command Line (EID)     |                              |
|                               |  | Parent command line (Sysmon,   |                              |
|                               |   CAR)                            |                              |
|                               |  | sha256_hash (CAR)              |                              |
+-------------------------------+-----------------------------------+------------------------------+
| Files                         |  | Original filename (Sysmon)     |                              |
+-------------------------------+-----------------------------------+------------------------------+
| Signatures                    |  | signer (CAR)                   |                              |
|                               |  | signature_valid (CAR)          |                              |
|                               |  | mime_type (CAR)                |                              |
|                               |  | link_target (Sysmon)           |                              |
+-------------------------------+-----------------------------------+------------------------------+
| Tool-specific configurations  |  | Integrity level (Sysmon, CAR)  | | File path outside adversary|
|                               |  | Mandatory Label (EID)          | | control                    |
|                               |  | Token elevation type (EID)     |                              |
|                               |  | Access level (CAR)             |                              |
+-------------------------------+-----------------------------------+------------------------------+
| User Session                  |  | Loging type (CAR)              |                              |
|                               |  | Login successful (CAR)         |                              |
+-------------------------------+-----------------------------------+------------------------------+
| Authentication                |  | Auth service (CAR)             |                              |
|                               |  | Decision reason (CAR)          |                              |
|                               |  | Method (CAR)                   |                              |
+-------------------------------+-----------------------------------+------------------------------+

