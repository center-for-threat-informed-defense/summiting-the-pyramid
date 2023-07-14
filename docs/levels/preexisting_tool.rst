.. _Pre-Existing Tools:

-----------------------------------
Level 3: Core to Pre-Existing Tools
-----------------------------------

**Description**: Observables associated with a tool or functionality that existed on the system pre-compromise, may be managed by the defending organization, and difficult for an adversary to modify.

**Why are tools split between adversary brought and pre-existing?**

Pre-existing tools provide less flexibility to adversaries than tools that are brought by an adversary, as an adversary has to behave and act with what is available to them through the tool. 
The configurations, command-line arguments, and other observables for this level will remain consistent with what is available for the tool.

Since the adversary cannot change the capability itself and it is managed by an organization, it is much more difficult to distinguish adversary behavior 
from benign behavior. This provides an opportunity for an adversary to blend into the computing environment, also known as a Living off the Land (LotL) attack [#f1]_ [#f2]_. 
It is likely that analytics utilizing native tool observables will need to be combined with other level’s observables, or require further research into 
low-variance behaviors of abusing these tools through MITRE ATT&CK techniques.

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
| User Session                  |  | Login  type (CAR)              |                              |
|                               |  | Login successful (CAR)         |                              |
+-------------------------------+-----------------------------------+------------------------------+
| Authentication                |  | Auth service (CAR)             |                              |
|                               |  | Decision reason (CAR)          |                              |
|                               |  | Method (CAR)                   |                              |
+-------------------------------+-----------------------------------+------------------------------+

.. rubric:: References

.. [#f1] https://darktrace.com/blog/living-off-the-land-how-hackers-blend-into-your-environment
.. [#f2] https://www.gdatasoftware.com/blog/2022/02/37248-living-off-the-land
