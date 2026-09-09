.. _measuring-detection-coverage:

Measuring Detection Coverage
============================

Detection coverage is more than the presence of an analytic mapped to an
ATT&CK technique. Meaningful coverage requires understanding both how much of
the behavior can be detected and the quality of the detection logic providing
that coverage.

The Summiting the Pyramid approach evaluates these questions through two
complementary concepts:

* **Detection Quality** evaluates the robustness and precision of detection
  logic.
* **Implementation Coverage** evaluates how much of the known behavioral
  implementation space for an ATT&CK technique can be detected.

Together, these dimensions provide a more defensible picture of detection
coverage than a binary covered/uncovered designation.


Detection Quality
-----------------

Detection Quality describes the quality of the signals and logic used to detect
adversary behavior. It considers two complementary characteristics:

* **Robustness** — how difficult a detection signal is for an adversary to
  evade or manipulate.
* **Precision** — how well a detection signal distinguishes malicious behavior
  from benign activity.

A detection can perform well in one dimension without performing well in the
other. A highly specific indicator may provide strong evidence of known
malicious activity while being easy for an adversary to change. Conversely, an
observable that is difficult for an adversary to avoid may also occur frequently
during legitimate activity.

See :doc:`Detection Quality <detection-quality>` for detailed guidance on
these dimensions.


Implementation Coverage
-----------------------

Implementation Coverage describes how much of the known behavioral space for
an ATT&CK technique can be detected.

ATT&CK techniques can often be performed through multiple behaviorally
distinct execution paths, or **implementations**. These paths may produce
different system interactions and observable signals, meaning a detection
associated with a technique may provide visibility into some implementations
but not others.

See :doc:`Implementation Coverage <implementation-coverage>` for guidance on
identifying and measuring coverage across implementations.


Effective Detection Coverage
----------------------------

Detection Quality and Implementation Coverage answer different but
complementary questions:

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Dimension
     - Question
   * - **Detection Quality**
     - *How good are the detections providing coverage?*
   * - **Implementation Coverage**
     - *How much of the behavior can we detect?*

Considering both dimensions provides a more complete view of defensive
coverage. A detection set may cover many implementations using fragile or
ambiguous signals, while another may use highly robust and precise detections
for only a narrow portion of a technique's behavioral space.

The goal is not simply to maximize the number of ATT&CK techniques associated
with detection content. It is to understand the strength and depth of the
coverage behind those mappings.

See :doc:`Detection Coverage Calculator <detection-coverage-calculator>` for
guidance on automating this analysis.
