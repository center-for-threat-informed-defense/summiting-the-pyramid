.. _implementation-catalog:

Implementation Catalog
======================

The `Implementation Catalog <https://github.com/center-for-threat-informed-defense/summiting-the-pyramid/blob/stp3/DCC/implementation_catalog_with_attack_components.xlsx>`_ provides a structured, behavior-first
representation of the different ways ATT&CK techniques can be executed, with each technique having a common behavioral baseline for evaluating detection
coverage. Instead of treating each ATT&CK procedure example as a separate unit,
it organizes related examples into reusable implementations based on meaningful
differences in execution path and required system interactions.


How the Catalog Is Constructed
------------------------------

The catalog is built from ATT&CK procedure examples and `Atomic Red Team tests <https://www.atomicredteam.io/docs/atomic-red-team>`_.
These sources provide concrete evidence of how techniques can be performed and
are analyzed to identify behaviorally distinct execution paths. Tool, actor, and procedure-specific details are abstracted where they do not
represent meaningful differences for detection, while differences that affect
system interactions and observability are preserved. The resulting implementations provide reusable behavioral models for coverage
analysis.

AI-Assisted Catalog Development
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To build the Implementation Catalog at scale, we developed an `AI-assisted analysis pipeline <https://github.com/center-for-threat-informed-defense/summiting-the-pyramid/tree/stp3/DCC/implementation_pipeline>`_ that transforms existing ATT&CK and Atomic Red Team content into structured implementation data. The pipeline first collects ATT&CK techniques, sub-techniques, procedure examples, and available Atomic Red Team tests and organizes them into a standardized input for analysis. An LLM then analyzes this source material to identify behaviorally distinct implementation paths, decompose them into the system interactions required to perform the behavior, and produce structured catalog entries. Automated validation checks ensure that the resulting data follows the expected schema and corresponds to the techniques provided as input, after which individual technique results can be combined into the larger Implementation Catalog. This approach allows a large and diverse body of existing threat knowledge to be systematically normalized into reusable behavioral models for detection coverage analysis.



Behaviorally Distinct Implementation Paths
-------------------------------------------

Two examples represent different implementations when they accomplish the same
ATT&CK technique through meaningfully different execution paths or required
system interactions. This distinction matters because different paths may expose different
detection opportunities. An observable produced by one implementation may not
appear when the adversary uses another, while some system interactions may be
shared across multiple implementations. The catalog focuses on differences that matter for detection rather
than differences that are merely incidental to a particular procedure.


Required System Interactions
----------------------------

Each implementation is characterized by the system interactions required to
execute it. Required interactions shift the focus from *which tool the adversary used* to
*what the adversary had to cause the system to do*. These interactions provide
the connection between an ATT&CK behavior and the telemetry that can make that
behavior observable.


System-Interaction Taxonomy
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The system-interaction taxonomy provides a common vocabulary for describing
required system interactions consistently across implementations. Using a shared taxonomy allows similar interactions to be recognized across
different techniques, tools, and procedures and provides a consistent basis
for connecting implementations to telemetry.


Connections to Telemetry
--------------------------

System interactions become useful for detection only when defenders have
telemetry capable of observing them. Connecting implementation requirements to field-level telemetry mappings helps
identify where evidence of an implementation should appear and whether the
available telemetry contains enough information to support detection.

See :ref:`Field-Level Telemetry Mappings & Scoring
<field-level-telemetry-mappings>` for more information.


Using the Catalog for Coverage Analysis
---------------------------------------

The Implementation Catalog provides the behavioral baseline used to measure
:ref:`Implementation Coverage <implementation-coverage>`. For a mapped ATT&CK technique, detection logic can be evaluated against the
implementations represented in the catalog to determine which execution paths
are meaningfully observed.

The catalog is not intended to represent every possible procedure or
variation of a technique. Its purpose is to provide a useful, reusable
behavioral model for detection coverage analysis.
