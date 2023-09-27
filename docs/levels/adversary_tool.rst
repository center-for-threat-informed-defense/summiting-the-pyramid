.. _Adversary Brought Tool:

---------------------------------------
Level 2: Core to Adversary-Brought Tool
---------------------------------------

**Description**: Observables which are associated with tools that are brought in by an
adversary to accomplish an attack.

Tools which are brought by an adversary for an attack provide the adversary the
flexibility to configure the tool and change their implementations to meet their
specific needs. Malware and tools which might fall under these observables include
ADFind, Cobalt Strike, and others which the adversary can modify or configure to
accomplish their goal.

**Why are adversary-brought tools placed here?**

These tools give adversaries flexibility to evade detection by modifying the tool before
deployment to the target system. For example, if an analytic detection is identifying
certain tool-specific configurations, an adversary can change the source code and evade
that detection [#f1]_. While this requires knowledge on the adversary to change the tool
configuration without changing the functionality, it gives an adversary flexibility to
evade detection through the availability of application code itself.

**Examples**: Command-line arguments, tool-specific configurations, metadata, binaries

Observables
^^^^^^^^^^^
+-------------------------------+-----------------------------------+----------------------------------+--------------------------------+
| Category                      | Observables                       |   Generating Activity            |           Evade Behavior       |
+===============================+===================================+==================================+================================+
| Command-line arguments        |  | CommandLine (Sysmon)           | Built into the tool to identify  | Rename arguments within tool,  |
|                               |  | ParentCommandLine (Sysmon)     | different functionalities, be    | which requires access to code  |
|                               |                                   | called by a tool or script, or   | base. Need for recompile.      |
|                               |                                   | called by an interactive sessions|                                |
|                               |                                   | with a user                      |                                |
+-------------------------------+-----------------------------------+----------------------------------+--------------------------------+
| Process creation              |  | OriginalFileName (Sysmon)      | Filename is embedded into        | User would have to edit the PE |
|                               |                                   | the PE header of a tool          | header with the updated name   |
|                               |                                   |                                  | and recompile the tool         |
+-------------------------------+-----------------------------------+----------------------------------+--------------------------------+
| Tool-specific configurations  |  | Integrity level (Sysmon)       | A recommendation for setting     | Change setting within tool,    |
|                               |                                   | up and using tools that          | requires permissions to        |
|                               |                                   | support processing of            | reconfigure tool               |
|                               |                                   | information [#f2]_               |                                |
+-------------------------------+-----------------------------------+----------------------------------+--------------------------------+
| Metadata                      |  |                                | Created when a file is modified, | Recompile tool                 |
|                               |                                   | including its deletion [#f3]_    |                                |
+-------------------------------+-----------------------------------+----------------------------------+--------------------------------+
| Binaries                      |  |                                | Offered by programs which allow  | Utilize different binary,      |
|                               |                                   | a program to be installed without| edit binary directly, or       |
|                               |                                   | having to compile source code    | recompile source code with     |
|                               |                                   | [#f4]_                           | different options              |
+-------------------------------+-----------------------------------+----------------------------------+--------------------------------+

.. rubric:: References

.. [#f1] https://posts.specterops.io/capability-abstraction-fbeaeeb26384
.. [#f2] https://csrc.nist.gov/glossary/term/tool_configuration
.. [#f3] https://www.techtarget.com/whatis/definition/metadata
.. [#f4] https://www.computerhope.com/jargon/b/binaries.htm
