Understanding Detection Coverage
================================

Traditional approaches to detection coverage often focus on whether an analytic
is mapped to an ATT&CK technique. While these mappings are useful for organizing
defensive capabilities, they do not necessarily describe how much of the
technique can be detected or the quality of the detections providing that
coverage.

A technique may be performed in multiple behaviorally distinct ways, and a
detection that observes one of those paths may not observe others. At the same
time, the signals underlying that detection may vary in how difficult they are
for an adversary to evade and how well they distinguish malicious from benign
activity. Summiting the Pyramid addresses these dimensions through two complementary
concepts: **Detection Quality** and **Implementation Coverage**. Together, they provide a more evidence-based way to understand what sits behind
an ATT&CK coverage claim.


Detection Quality
-----------------

**Detection Quality** describes the quality of the signals and logic used to
detect adversary behavior. It considers two complementary characteristics:

* **Robustness** — how difficult a detection signal is for an adversary to
  evade or manipulate.
* **Precision** — how well a detection signal distinguishes malicious behavior
  from benign activity.

Considering both helps defenders understand not simply whether a behavior can
be detected, but how much confidence they can place in the detection providing
that visibility.

:ref:`Learn more about Detection Quality <detection-quality>`


Implementation Coverage
-----------------------

**Implementation Coverage** describes how much of the known behavioral space
for an ATT&CK technique can be detected. ATT&CK techniques can often be performed through multiple behaviorally distinct
execution paths, or **implementations**. These paths may produce different
system interactions and observable signals, meaning a detection associated with
a technique may provide visibility into some implementations but not others.

Implementation Coverage makes that distinction explicit by evaluating which
known implementations are meaningfully observed by detection logic. This
provides a measure of detection depth that goes beyond treating a technique as
simply covered or uncovered.

:ref:`Learn more about Implementation Coverage <implementation-coverage>`


Bringing the Two Together
-------------------------

Detection Quality and Implementation Coverage answer two different but
complementary questions:

.. list-table::
   :header-rows: 0
   :widths: 30 70

   * - **Detection Quality**
     - *How good are the detections providing coverage?*
   * - **Implementation Coverage**
     - *How much of the behavior can we detect?*

Together, they provide a more complete view of **detection
coverage**, helping defenders understand not only where detection capability
exists, but the strength and depth of that capability.
