Measuring Detection Coverage
============================

Detection coverage is more than the presence of an analytic mapped to an
ATT&CK technique. Meaningful coverage requires understanding both **how much
of the behavior can be detected** and **the quality of the detection logic
providing that coverage**.

The Summiting the Pyramid approach evaluates these questions through two
complementary concepts:

* **Detection Quality** evaluates the robustness and precision of detection
  logic.
* **Implementation Coverage** evaluates how much of the known behavioral
  implementation space for an ATT&CK technique can be detected.

Together, these dimensions provide a more defensible picture of coverage than
a binary covered/uncovered designation.


Detection Quality
-----------------

Detection Quality describes the quality of the signals and logic used to detect
adversary behavior. It considers two complementary characteristics:
**robustness** and **precision**.

Robustness measures how difficult a detection signal is for an adversary to
evade or manipulate. Precision measures how well that signal distinguishes
malicious behavior from benign activity.

A detection can perform well in one dimension without performing well in the
other. A highly specific indicator may precisely identify known malicious
activity but be easy for an adversary to change. Conversely, an unavoidable
system interaction may be highly robust but occur frequently during legitimate
activity.

Considering both provides a more complete picture of the quality of the
detection logic.


Robustness
~~~~~~~~~~

Robustness measures how difficult a detection signal is for an adversary to
evade or manipulate.

Signals based on attacker-controlled values—such as filenames, hashes, or
specific command-line arguments—may be effective when those values appear but
relatively inexpensive for an adversary to change. More robust detections rely
on behaviors and system interactions that are increasingly difficult to avoid
while still accomplishing the adversary's objective.

At the highest levels of robustness, evasion requires a meaningful change in
implementation or abandonment of the technique altogether.


Precision
~~~~~~~~~

Precision measures how well a detection signal distinguishes malicious behavior
from benign activity.

A signal may be unavoidable for an adversary but also occur frequently during
legitimate operations. In those cases, additional context may be necessary to
determine whether the observed activity is malicious. Conversely, a highly
specific signal may provide strong confidence when observed while remaining
relatively easy for an adversary to change.

Precision complements robustness by evaluating not how difficult a signal is to
evade, but how confidently it can contribute to an actionable detection.


Distinguishing Malicious from Benign Activity
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Telemetry tells us that activity occurred; detection logic must provide enough
context to determine what that activity means.

An event or field alone may describe a system interaction without
distinguishing legitimate use from adversary behavior. High-quality detection
logic incorporates the observable fields and conditions necessary to narrow
that ambiguity and establish stronger evidence of the behavior being detected.

This distinction is especially important for common system activity. Collecting
the right telemetry is a prerequisite for detection, but visibility alone does
not establish malicious behavior.


Precision Scoring
^^^^^^^^^^^^^^^^^

Precision scoring evaluates the discriminating value of the signals used by
detection logic.

Signals that provide little context for separating malicious from benign
activity receive lower precision, while signals and combinations of conditions
that more specifically characterize the behavior of interest receive higher
precision.

Precision should be interpreted alongside robustness rather than as a
standalone measure. Increasing specificity can improve confidence in a signal
while also making that signal more dependent on details an adversary can
change.


Implementation Coverage
-----------------------

Implementation Coverage measures how much of the known behavioral space for an
ATT&CK technique can be meaningfully detected.

An ATT&CK technique may be accomplished through multiple execution paths that
produce different system interactions and observable signals. As a result,
having an analytic mapped to a technique does not necessarily mean that
every—or even most—ways of performing that technique can be detected.

Implementation Coverage makes that distinction measurable by evaluating
detection logic against known implementations of the mapped technique.


What Is an Implementation?
~~~~~~~~~~~~~~~~~~~~~~~~~~

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
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

Procedure examples contain valuable evidence about how adversaries perform
techniques, but their incidental details can make individual examples too
specific to serve as reusable units of coverage. Implementations abstract away
those details while retaining meaningful behavioral differences.

This gives defenders a unit of analysis that is specific enough to measure
detection coverage while remaining reusable across individual tools, actors,
and procedures.


Implementation Catalog
~~~~~~~~~~~~~~~~~~~~~~

The **Implementation Catalog** provides a structured representation of
behaviorally distinct ways ATT&CK techniques can be executed.



Measuring Implementation Coverage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Implementation Coverage compares the implementations meaningfully observed by
detection logic against the known implementations represented for the mapped
ATT&CK technique.

For example, if eight implementations are represented for a technique and
available detections meaningfully observe two, the resulting coverage can be
expressed as **2/8 implementations**.

This does not imply that the remaining six implementations are necessarily
undetectable. Rather, it identifies where the evaluated detection content does
not currently provide sufficient evidence of coverage.

The objective is therefore not simply to maximize a percentage. Implementation
Coverage is intended to expose where coverage is broad, where it is narrow, and
where additional detection logic or telemetry may provide the greatest
benefit.


Effective Detection Coverage
----------------------------

Effective Detection Coverage considers **Detection Quality and Implementation
Coverage together**.

Implementation Coverage describes the breadth of behavior that can be detected.
Detection Quality describes the robustness and precision of the signals
providing that coverage. Neither dimension alone provides a complete picture.

A detection program may cover many implementations using fragile or ambiguous
signals, or it may have highly robust and precise detections for only a narrow
portion of a technique's behavioral space. Understanding both dimensions
provides a more meaningful basis for evaluating defensive coverage.


Combining Detection Quality & Implementation Coverage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Detection Quality and Implementation Coverage answer different but
complementary questions:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Dimension
     - Question
   * - **Implementation Coverage**
     - *How much of the behavior can we detect?*
   * - **Robustness**
     - *How difficult is that detection to evade?*
   * - **Precision**
     - *How well does it distinguish malicious from benign activity?*

Together, they shift coverage measurement from *"Do we have a detection mapped
to this technique?"* toward *"Which ways of performing this technique can we
detect, and how much confidence should we place in those detections?"*


Understanding Coverage Gaps
~~~~~~~~~~~~~~~~~~~~~~~~~~~

A coverage gap can have several causes, and identifying the cause is often more
useful than the score itself.

A gap may indicate that:

* an implementation is not addressed by existing detection logic;
* the required telemetry is not collected or lacks the necessary fields;
* an analytic relies on signals that do not sufficiently demonstrate the
  mapped behavior;
* an ATT&CK mapping is inaccurate or outdated; or
* the analytic observes a tool or potential precursor to behavior rather than
  the behavior itself.

Coverage analysis helps separate these problems so defenders can determine
whether the appropriate response is to improve an analytic, collect different
telemetry, correct a mapping, or develop new detection content.


Detection Depth vs. Detection Quantity
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Detection quantity measures how much detection content exists or how many
ATT&CK techniques have analytics mapped to them. **Detection depth asks how
much meaningful defensive capability exists behind those mappings.**

Adding another ATT&CK tag can increase apparent coverage without adding
telemetry, analytic logic, or the ability to detect additional adversary
behavior. Implementation Coverage instead asks what behavior the analytic
actually observes and which implementations that evidence supports.

The goal is not necessarily to produce more green boxes. It is to make the
green boxes more meaningful.
