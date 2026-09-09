.. _Adversary Brought Tool:

Level 2: Implementation / Attacker-Controlled
=============================================

**Description:** Observables that describe how an adversary chose to implement
an attack, including tooling, infrastructure, or configuration choices that the
adversary can modify.

Level 2 observables are tied to characteristics of a particular implementation
rather than the underlying behavior itself. An adversary may be able to
reconfigure tooling, modify infrastructure, or change implementation details
without changing the overall objective of the attack. Because these observables reflect attacker-controlled choices, they can often
be changed without requiring the adversary to substantially change the
underlying behavior.


Why are these observables placed at Level 2?
--------------------------------------------

An adversary who controls the implementation has significant flexibility to
change the observables associated with it. For example, an adversary may
reconfigure a tool, modify command-line arguments, change a binary, or alter
other implementation-specific details while preserving the same functionality. Evading a Level 2 observable generally requires **reconfiguring tooling or
infrastructure**, rather than changing the underlying attack behavior. Level 2 therefore represents a meaningful step above ephemeral values, but
the detection remains dependent on the adversary's choice of implementation.


Examples
--------

Examples of Level 2 observables include:

* Command-line arguments specific to an implementation
* Tool-specific configurations
* Implementation-specific metadata
* Binaries or other implementation-specific artifacts


Observables
-----------

The examples below illustrate common Level 2 observables and how an adversary
may modify them to evade detection.

.. list-table::
   :header-rows: 1
   :widths: 22 23 35 20

   * - Category
     - Observable
     - Generating Activity
     - Evade Behavior

   * - Command-Line Arguments
     - ``CommandLine`` (Sysmon), ``ParentCommandLine`` (Sysmon)
     - Arguments used to select or configure functionality within a tool or
       implementation.
     - Reconfigure or modify the implementation so that different arguments
       are used.

   * - Process Creation
     - ``OriginalFileName`` (Sysmon)
     - The original filename embedded in a portable executable.
     - Modify the binary or use a different binary.

   * - Tool-Specific Configurations
     - Implementation-specific configuration values
     - Configuration settings that determine how a tool operates.
     - Reconfigure the tool or use a different configuration.



.. rubric:: References

.. [#f1] https://posts.specterops.io/capability-abstraction-fbeaeeb26384
.. [#f2] https://csrc.nist.gov/glossary/term/tool_configuration
.. [#f3] https://www.techtarget.com/whatis/definition/metadata
.. [#f4] https://www.computerhope.com/jargon/b/binaries.htm
