.. _Adversary Brought Tool:

---------------------------------------
Level 2: Core to Adversary-Brought Tool
---------------------------------------

**Description**: Observables which are associated with tools that are brought in by an adversary to accomplish an attack. 

Tools which are brought by an adversary for an attack provide the adversary the flexibility to configure the tool and change their implementations to meet their specific needs. Tools which might fall under these observables include 
ADFind, Cobalt Strike, and others which the adversary can modify or configure to accomplish their goal.

**Why are adversary-brought tools placed here?**

These tools gives adversaries an additional outlet of configuration to evade certain detections. For example, if an analytic detection is 
identifying certain tool-specific configurations, an adversary can go into the open-source code, change it, and evade that detection [#f1]_. While this 
requires knowledge on the adversary to change the tool configuration without changing the capability, it gives an adversary flexibility to 
evade detection through the availability of application code itself. Even if an adversary does not have the power to configure the tool itself, them having control over the tool during an attack gives them the advantage over the adversary.

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