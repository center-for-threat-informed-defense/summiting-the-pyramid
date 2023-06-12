.. _Tools Within Adversary Control:

---------------------------------------
Level 2: Tools Within Adversary Control
---------------------------------------

**Description**: These are tools that are custom-made or can be configured by the adversary, which they control the code, functions, and binaries associated with them.

Tools which are within adversary control provide users the flexibility to configure the tool to meet their specific needs. These include items such as 
ADFind, Cobalt Strike, and others which the adversary can modify or configure to accomplish their goal.

**Why are tools within adversary control placed here?**

These tools gives adversaries an additional outlet of configuration to evade certain detections. For example, if an analytic detection is 
identifying certain tool-specific configurations, an adversary can go into the open-source code, change it, and evade that detection [#f1]_. While this 
requires knowledge on the adversary to change the tool configuration without changing the capability, it gives an adversary flexibility to 
evade detection through the availability of application code itself.

**Examples**: Signatures, command-line arguments, tool-specific configurations, metadata, binaries

Observables
^^^^^^^^^^^
+-------------------------------+-----------------------------------+------------------------------+
| Category                      | Observable Fields                 |   Observable Values          |
+===============================+===================================+==============================+
| Command-line arguments        |  | Command line (Sysmon)          |                              |
|                               |  | Parent command line (Sysmon)   |                              |
|                               |  | sha256_hash (CAR)              |                              |
+-------------------------------+-----------------------------------+------------------------------+
| Files                         |  | Original filename (Sysmon)     |                              |
+-------------------------------+-----------------------------------+------------------------------+
| Signatures                    |  |                                |                              |
+-------------------------------+-----------------------------------+------------------------------+
| Tool-specific configurations  |  | Integrity level (Sysmon)       |                              |
+-------------------------------+-----------------------------------+------------------------------+
| Metadata                      |  |                                |                              |
+-------------------------------+-----------------------------------+------------------------------+
| Binaries                      |  |                                |                              |
+-------------------------------+-----------------------------------+------------------------------+

.. rubric:: References

.. [#f1] https://posts.specterops.io/capability-abstraction-fbeaeeb26384