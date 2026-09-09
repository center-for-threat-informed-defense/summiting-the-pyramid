.. _implementation-catalog:

Implementation Catalog
======================

The **Implementation Catalog** provides a structured, behavior-first
representation of the different ways ATT&CK techniques can be executed.

The catalog provides a common behavioral baseline for evaluating detection
coverage. Instead of treating each ATT&CK procedure example as a separate unit,
it organizes related examples into reusable implementations based on meaningful
differences in execution path and required system interactions.


How the Catalog Is Constructed
------------------------------

The catalog is built from ATT&CK procedure examples and Atomic Red Team tests.
These sources provide concrete evidence of how techniques can be performed and
are analyzed to identify behaviorally distinct execution paths.

Tool-, actor-, and procedure-specific details are abstracted where they do not
represent meaningful differences for detection, while differences that affect
system interactions and observability are preserved.

The resulting implementations provide reusable behavioral models for coverage
analysis.


ATT&CK Procedure Examples & Atomic Red Team Tests
-------------------------------------------------

ATT&CK procedure examples provide real-world examples of how adversaries have
performed techniques. Atomic Red Team tests provide concrete, executable
examples of technique behavior.

Using both sources provides a broader foundation for identifying practical
implementation paths. The objective is not to treat every procedure or test
as a distinct implementation, but to identify the meaningful behavioral
differences that affect detection opportunities.


Behaviorally Distinct Implementation Paths
-------------------------------------------

Two examples represent different implementations when they accomplish the same
ATT&CK technique through meaningfully different execution paths or required
system interactions.

This distinction matters because different paths may expose different
detection opportunities. An observable produced by one implementation may not
appear when the adversary uses another, while some system interactions may be
shared across multiple implementations.

The catalog therefore focuses on differences that matter for detection rather
than differences that are merely incidental to a particular procedure.


Required System Interactions
----------------------------

Each implementation is characterized by the system interactions required to
execute it.

Required interactions shift the focus from *which tool the adversary used* to
*what the adversary had to cause the system to do*. These interactions provide
the connection between an ATT&CK behavior and the telemetry that can make that
behavior observable.


System-Interaction Taxonomy
---------------------------

The **system-interaction taxonomy** provides a common vocabulary for describing
required system interactions consistently across implementations.

Using a shared taxonomy allows similar interactions to be recognized across
different techniques, tools, and procedures and provides a consistent basis
for connecting implementations to telemetry.


Connections to Telemetry
------------------------

System interactions become useful for detection only when defenders have
telemetry capable of observing them.

Connecting implementation requirements to field-level telemetry mappings helps
identify where evidence of an implementation should appear and whether the
available telemetry contains enough information to support detection.

See :doc:`Field-Level Telemetry Mappings & Scoring
<field-level-telemetry-mappings>` for more information.


Using the Catalog for Coverage Analysis
---------------------------------------

The Implementation Catalog provides the behavioral baseline used to measure
:doc:`Implementation Coverage <implementation-coverage>`.

For a mapped ATT&CK technique, detection logic can be evaluated against the
implementations represented in the catalog to determine which execution paths
are meaningfully observed.

The catalog is therefore not intended to represent every possible procedure or
variation of a technique. Its purpose is to provide a useful, reusable
behavioral model for detection coverage analysis.
