Detection Quality
=================

Detection Quality describes the quality of the signals and logic used to detect
adversary behavior. It considers two complementary characteristics:
**robustness** and **precision**.

* **Robustness** considers how difficult a detection signal is for an adversary
  to evade or manipulate.
* **Precision** considers how well a detection signal distinguishes malicious
  behavior from benign activity.

A detection can perform well in one dimension without performing well in the
other. A highly specific indicator may provide strong evidence of known
malicious activity but be easy for an adversary to change. Conversely, an
observable tied to a system interaction that an adversary cannot easily avoid
may also occur frequently during legitimate activity.

Considering both provides a more complete picture of the quality of detection
logic and the trade-offs involved in improving it.


Balancing Robustness and Precision
----------------------------------

Robustness and precision describe different properties of a detection, and
improving one does not necessarily improve the other.

For example, a detection based on a known malicious hash may be highly
discriminating when that exact value is observed. However, the adversary can
usually change the file—and therefore its hash—without changing the underlying
behavior. The signal may provide strong confidence when it appears while
providing little resistance to evasion.

At the other extreme, a detection may observe a system interaction that is
required across many implementations of a technique. This can provide durable
visibility because the adversary has fewer opportunities to avoid the
observable. But if the same interaction occurs frequently during legitimate
activity, the signal alone may not provide enough information to distinguish
malicious behavior.

This means that the strongest detection is not always the most specific signal
or the signal that covers the most behavior. Detection engineers should
consider both dimensions and determine what combination of evidence provides
useful visibility for the behavior and environment being monitored.

Where a robust signal lacks sufficient precision, additional fields,
conditions, environmental information, or correlated activity may provide the
context needed to distinguish malicious from benign behavior. Where a precise
signal is easily changed, more durable behavioral observables may provide
additional resistance to adversary evasion.

See :ref:`High-Quality Detection Design Principles
<high-quality-detection-design-principles>` for guidance on applying these
trade-offs when designing detection logic.


Robustness
----------

Robustness measures how difficult a detection signal is for an adversary to
evade or manipulate.

Signals based on attacker-controlled values—such as filenames, hashes, or
specific command-line arguments—may be effective when those values appear but
relatively inexpensive for an adversary to change. More robust signals rely on
behaviors and system interactions that become increasingly difficult to avoid
while still accomplishing the adversary's objective.

The Summiting the Pyramid model describes this progression through
:ref:`Summiting Levels <summiting-levels>`. As signals move from ephemeral and
attacker-controlled observables toward system-constrained and invariant
behaviors, the changes required to evade them become increasingly significant.

At the highest levels of robustness, evasion may require the adversary to
substantially change how the behavior is implemented or abandon the technique
altogether.

Robustness should be considered over time as well as against known activity
today. A detection built around one current tool or implementation may perform
well against that activity while failing when the adversary changes an
incidental detail. Robust detections seek observables that remain relevant
across changes in tools and implementations.

See :ref:`Summiting Levels <summiting-levels>`,
:ref:`Combining Observables <combining-observables>`, and
:ref:`Scoring Resistance to Adversary Evasion
<scoring-resistance-to-adversary-evasion>` for detailed guidance on evaluating
robustness.


Precision
---------

Precision describes how well a detection signal distinguishes malicious
behavior from benign activity.

A signal can be highly robust while still providing limited information about
intent. For example, an operating system interaction required by an ATT&CK
technique may also occur routinely during legitimate administration. Detecting
the interaction provides visibility, but additional evidence may be necessary
to determine whether the activity is malicious.

Precision can be improved by incorporating fields, values, conditions, or
context that more specifically characterize the behavior of interest. The
appropriate evidence will depend on both the behavior and the environment in
which the detection operates.

This does not mean that detection logic should simply become as specific as
possible. Adding highly specific conditions can reduce unwanted alerts while
also narrowing the activity the analytic can detect or introducing conditions
an adversary can manipulate. Precision should therefore be considered
alongside robustness rather than optimized independently.

See :ref:`Using Context to Determine Intent
<using-context-to-determine-intent>` for guidance on distinguishing ambiguous
behavior and :ref:`Field-Level Telemetry Mappings & Scoring
<field-level-telemetry-mappings>` for guidance on understanding the information
available within telemetry.


Combining Evidence
------------------

A single signal does not always provide both strong robustness and strong
precision.

Detection logic can combine multiple pieces of evidence to improve Detection
Quality. A durable behavioral observable may establish that an important system
interaction occurred, while additional fields or contextual signals help
determine whether that interaction is suspicious or malicious.

When adding conditions, filters, or exclusions, consider their effect on both
dimensions. A condition that reduces benign alerts may improve precision but
also create an opportunity for an adversary to evade the analytic. Likewise,
broadening an analytic to observe additional implementations may improve
visibility while introducing activity that requires additional context.

The objective is not necessarily to produce a single analytic that perfectly
optimizes every dimension. In some cases, multiple analytics or correlated
observations may provide a better balance.

See :ref:`Chaining Analytics <chaining-analytics>` for guidance on combining
multiple analytics when additional context is required.


Detection Quality in Coverage
-----------------------------

Detection Quality describes the strength of the detection logic providing
coverage, but it does not describe how much of an ATT&CK technique's behavioral
space is detected.

That question is addressed through :ref:`Implementation Coverage
<implementation-coverage>`.

Considering Detection Quality and Implementation Coverage together helps
distinguish between different kinds of defensive capability. A detection may
use robust, precise signals while observing only a narrow portion of a
technique's implementations. Another detection set may observe many
implementations but rely on signals that are fragile or difficult to
distinguish from legitimate activity.

See :ref:`Measuring Detection Coverage <measuring-detection-coverage>` for
guidance on using these dimensions together to evaluate detection coverage.
