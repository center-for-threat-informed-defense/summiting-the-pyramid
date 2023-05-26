---------------------------------------
Level 2: Tools within Adversary Control
---------------------------------------

**Description**: These are tools that are custom-made or can be configured by the adversary, which they control the code, functions, and binaries associated with them.

**Examples**: Signatures, command-line arguments, tool-specific configurations, metadata, binaries

Observables
^^^^^^^^^^^
+-------------------------------+-----------------------------------+------------------------------+
| Category                      | Observable Fields                 |   Observable Values          |
+===============================+===================================+==============================+
| Command-line arguments        |  | Command line (Sysmon)          |                              |
|                               |  | Integrity level (Sysmon)       |                              |
|                               |  | Parent command line (Sysmon)   |                              |
|                               |  | sha256_hash (CAR)              |                              |
+-------------------------------+-----------------------------------+------------------------------+
| Files                         |  | Original filename (Sysmon)     |                              |
+-------------------------------+-----------------------------------+------------------------------+

