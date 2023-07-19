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
+-------------------------------+-----------------------------------+------------------------------+--------------------------------+
| Category                      | Observables                       | Generating Activity          |  Evade Behavior                |
+===============================+===================================+==============================+================================+
| Command-line arguments        |  | Command line (Sysmon, CAR)     | Built into the tool to       | Change the tool or             |
|                               |  | Process Command Line (EID)     | identify different           | configuration which has        |
|                               |  | Parent command line (Sysmon,   | functionalities              | different command-line         |
|                               |   CAR)                            |                              | arguments                      |
|                               |  | sha256_hash (CAR)              |                              |                                |
+-------------------------------+-----------------------------------+------------------------------+--------------------------------+
| Files                         |  | Original filename (Sysmon)     | Filename is embedded into the| Use a tool with a different    |
|                               |                                   | PE header of a tool          | filename                       |
+-------------------------------+-----------------------------------+------------------------------+--------------------------------+
| Signatures                    |  | signer (CAR)                   |                              |                                |
|                               |  | signature_valid (CAR)          |                              |                                |
|                               |  | mime_type (CAR)                |                              |                                |
|                               |  | link_target (Sysmon)           |                              |                                |
+-------------------------------+-----------------------------------+------------------------------+--------------------------------+
| Tool-specific configurations  |  | Integrity level (Sysmon, CAR)  | A recommendation for setting | Pivot to tool or raise         |
|                               |  | Mandatory Label (EID)          | up and using tools that      | permissions to avoid alerts    |
|                               |  | Token elevation type (EID)     | support processing of        | on specific-configuration      |
|                               |  | Access level (CAR)             | information [#f3]_           |                                |
|                               |  | File path outside adversary    |                              |                                |
|                               |   control                         |                              |                                |
+-------------------------------+-----------------------------------+------------------------------+--------------------------------+
| User Session                  |  | Login type (CAR)               | A user logons to a profile or| Login to application or user   |
|                               |  | Login successful (CAR)         | application [#f4]_           | with different logon type      |
+-------------------------------+-----------------------------------+------------------------------+--------------------------------+
| Authentication                |  | Auth service (CAR)             |                              |                                |
|                               |  | Decision reason (CAR)          |                              |                                |
|                               |  | Method (CAR)                   |                              |                                |
+-------------------------------+-----------------------------------+------------------------------+--------------------------------+

.. rubric:: References

.. [#f1] https://darktrace.com/blog/living-off-the-land-how-hackers-blend-into-your-environment
.. [#f2] https://www.gdatasoftware.com/blog/2022/02/37248-living-off-the-land
.. [#f3] https://csrc.nist.gov/glossary/term/tool_configuration
.. [#f4] https://auth0.com/docs/manage-users/sessions
