Implementation Coverage
=======================

Implementation Coverage measures how much of the known behavioral space for an
ATT&CK technique can be meaningfully detected.

An ATT&CK technique may be accomplished through multiple execution paths that
produce different system interactions and observable signals. As a result,
having an analytic mapped to a technique does not necessarily mean that every,
or even most, ways of performing that technique can be detected.

Implementation Coverage makes this distinction measurable by evaluating
detection logic against known implementations of the mapped technique.


What Is an Implementation?
--------------------------

An **implementation** is a behaviorally distinct way of executing an ATT&CK
technique, characterized by its execution path and the system interactions
required to perform it.

For example, an adversary creating a scheduled task might use PowerShell,
directly modify the Windows Registry, invoke ``schtasks.exe`` from the command
line, or use an XML task definition. Each achieves the same ATT&CK behavior,
but the path taken—and the observable activity it produces—can differ.

Distinguishing these implementations allows defenders to reason about which
ways of performing a technique they can actually observe rather than treating
a single technique mapping as evidence of complete coverage.


Technique → Implementation → Procedure
---------------------------------------

Implementations provide a behavioral layer between ATT&CK techniques and
procedure examples.

**Technique**

  Describes adversary behavior at a broad, reusable level.

↓

**Implementation**

  Describes a behaviorally distinct way of accomplishing that technique based
  on its execution path and required system interactions.

↓

**Procedure**

  Describes a specific instance of that behavior, often involving a particular
  actor, tool, command, or configuration.

Procedure examples provide valuable evidence about how adversaries perform
techniques, but their incidental details can make individual examples too
specific to serve as reusable units of coverage. Implementations abstract away
those details while retaining meaningful behavioral differences.

This provides a unit of analysis that is specific enough to measure detection
coverage while remaining reusable across tools, actors, and procedures.


Implementation Catalog
----------------------

The :doc:`Implementation Catalog <implementation-catalog>` provides a
structured representation of behaviorally distinct ways ATT&CK techniques can
be executed.

The catalog provides the behavioral baseline needed to evaluate which known
ways of performing a technique can be observed by detection logic.


Measuring Implementation Coverage
---------------------------------

Implementation Coverage compares the implementations meaningfully observed by
detection logic against the known implementations represented for the mapped
ATT&CK technique.

For example, if eight implementations are represented for a technique and
available detections meaningfully observe two, the resulting coverage can be
expressed as **2/8 implementations**.

This does not imply that the remaining six implementations are necessarily
undetectable. Rather, it identifies where the evaluated detection content does
not currently provide sufficient evidence of coverage.

The objective is not simply to maximize a percentage. Implementation Coverage
is intended to expose where coverage is broad, where it is narrow, and where
additional detection logic or telemetry may provide the greatest benefit.


Understanding Coverage Gaps
---------------------------

A coverage gap can have several causes, and identifying the cause is often
more useful than the score itself.

A gap may indicate that:

* an implementation is not addressed by existing detection logic;
* the required telemetry is not collected or lacks the necessary fields;
* an analytic relies on signals that do not sufficiently demonstrate the
  mapped behavior;
* an ATT&CK mapping is inaccurate or outdated; or
* the analytic observes a tool or potential precursor to behavior rather than
  the behavior itself.

Coverage analysis can help separate these problems so defenders can determine
whether the appropriate response is to improve an analytic, collect different
telemetry, correct a mapping, or develop new detection content.

See :doc:`Field-Level Telemetry Mappings & Scoring
<field-level-telemetry-mappings>` for guidance on connecting system
interactions to available telemetry.


Detection Depth vs. Detection Quantity
--------------------------------------

Detection quantity measures how much detection content exists or how many
ATT&CK techniques have analytics mapped to them. **Detection depth** asks how
much meaningful defensive capability exists behind those mappings.

Adding another ATT&CK tag can increase apparent coverage without adding
telemetry, analytic logic, or the ability to detect additional adversary
behavior. Implementation Coverage instead asks what behavior the analytic
actually observes and which implementations that evidence supports.

The goal is not necessarily to produce more green boxes. It is to make the
green boxes more meaningful.


Detection Quality and Implementation Coverage
----------------------------------------------

Implementation Coverage describes the breadth of behavior detected, while
:doc:`Detection Quality <detection-quality>` describes the quality of the
signals providing that coverage.

Both dimensions are necessary to understand the defensive value of a
detection.
