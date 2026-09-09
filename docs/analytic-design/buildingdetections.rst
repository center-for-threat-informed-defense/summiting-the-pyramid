.. _high-quality-detection-design-principles:

High-Quality Detection Design Principles
========================================

High-quality detections do more than identify activity associated with an
adversary. They provide meaningful evidence that the behavior of interest is
actually occurring while remaining difficult for an adversary to evade.

Building detections this way requires thoughtful decisions about the signals
used by an analytic, the behavior those signals represent, and the context
needed to interpret them.

The principles below provide guidance for making those decisions throughout
the :ref:`Detection Engineering Workflow <detection-engineering-workflow>`.


Detection Quality as a Design Goal
----------------------------------

Detection Quality considers two complementary characteristics of detection
logic: robustness and precision.

A detection may perform well in one dimension without performing well in the
other. A highly specific indicator may provide strong evidence of known
malicious activity but be easy for an adversary to change. Conversely, an
observable tied to a system interaction that an adversary cannot easily avoid
may also occur frequently during legitimate activity.

This creates an important design trade-off. Detection engineers should seek
signals that provide durable visibility while also supplying enough
information to distinguish the behavior of interest.

There is not always a single ideal balance. The appropriate detection logic
will depend on the behavior, available telemetry, operational requirements,
and environment in which the analytic will run.

See :ref:`Detection Quality <detection-quality>` for detailed guidance on
robustness and precision.


Selecting High-Quality Signals
------------------------------

The signals used by an analytic determine both what it can detect and how
easily an adversary can evade it.

Highly specific indicators such as hashes, filenames, process names, or
command-line strings can be valuable, particularly when detecting known
activity. However, these signals are often under adversary control and may
disappear with relatively inexpensive changes.

For detections intended to provide durable behavioral coverage, favor
observables tied to system interactions and behaviors that become increasingly
difficult for an adversary to avoid while still accomplishing their objective.

Signal selection should also consider the information an observable provides.
A system interaction may be unavoidable for an adversary but occur frequently
during legitimate activity. In those cases, additional fields, conditions, or
contextual signals may be necessary.

A useful signal therefore balances two questions:

* How difficult is this signal for an adversary to avoid?
* How much information does it provide for distinguishing the behavior of
  interest?

Whenever possible, combine durable behavioral signals with enough context to
make the resulting detection meaningful.

The :ref:`Detection Decomposition Diagram (D3)
<d3>` can help identify useful observables across
implementations, while :ref:`Field-Level Telemetry Mappings & Scoring
<field-level-telemetry-mappings>` can help determine what evidence is
available within the underlying telemetry.


Detecting Behavior vs. Tools
----------------------------

Tools provide useful detection opportunities, but detecting a tool is not
necessarily the same as detecting the behavior that tool can perform.

An analytic may identify a particular executable, service name, command
string, or utility associated with an ATT&CK technique. That detection may be
highly effective for the known activity. But if an adversary can rename the
tool, modify the command, use another utility, or accomplish the same objective
through another implementation, the behavior has not disappeared—the
observable has.

For detections intended to provide durable behavioral coverage, ask:

**What does the adversary have to cause the system to do in order to
accomplish this behavior?**

Detection logic built around required system interactions is generally more
reusable across tools and implementations than logic tied exclusively to the
identity of a particular tool.

Tool- and indicator-based detections still have important uses, particularly
for known threats, threat hunting, and rapid response. The key is to understand
what the analytic actually observes and avoid claiming broader behavioral
coverage than the logic supports.

See :ref:`Implementation Coverage <implementation-coverage>` for guidance on
evaluating detection across behaviorally distinct ways of performing a
technique.


Avoiding Inferred Intent
------------------------

Detection logic should distinguish between observing adversary behavior and
observing activity that *could be used* to perform adversary behavior.

Many legitimate tools and system functions can also be used maliciously.
Observing one of those tools does not, by itself, establish an attacker's
intent or demonstrate that a particular ATT&CK behavior occurred.

For example, reasoning that *"an adversary could use this utility to perform
Technique X, therefore detecting the utility detects Technique X"* relies on
inferred intent rather than direct evidence of the behavior. That observation
may provide a useful lead for threat hunting, but it is a weaker basis for
claiming detection coverage.

When evaluating detection logic, ask:

**What observable evidence demonstrates that the behavior is actually
occurring?**

If answering that question requires assumptions about what an adversary
*might* be doing or what they *might* do next, additional context may be
necessary.

Inference cannot always be eliminated. Some behaviors are inherently
ambiguous, and no single observable may establish malicious intent on its own.
The goal is to recognize when intent is being inferred and incorporate
additional evidence where necessary.

See :ref:`Using Context to Determine Intent
<Context>` for guidance on incorporating contextual
evidence.


Designing for the Environment
-----------------------------

A detection must work in the environment in which it is deployed.

Behavior that is unusual in one organization may be routine in another.
Environmental baselines, user roles, system functions, applications, and
organizational policies can all influence whether an observable is useful for
distinguishing malicious from legitimate activity.

Testing against representative environmental data can help identify recurring
benign behavior and determine where additional context or exclusions may be
necessary.

Exclusions should be introduced carefully. An exclusion reduces unwanted
alerts by deliberately creating an area in which the analytic will not fire.
If that area is too broad or easily reproduced by an adversary, the exclusion
can become an evasion opportunity.

When designing exclusions:

* prefer specific, known benign activity over broad categories;
* consider how much control an adversary has over the excluded values;
* understand the blind spot created by the exclusion; and
* periodically review whether the exclusion remains necessary and safe.

The objective is not to eliminate every false positive at the expense of
visibility. It is to achieve a useful operational balance while preserving the
detection's ability to observe adversary behavior.


When a Single Analytic Is Not Enough
------------------------------------

Some behaviors cannot be reliably distinguished as malicious based on a single
observable or analytic.

In these situations, multiple observations may collectively provide the
context needed to make a stronger determination. Individually common
activities, for example, may become significant when several occur for the
same user or system or when they appear as part of a recognizable sequence of
adversary behavior.

Correlation is most useful when the relationship between observations provides
information that the individual analytics cannot provide independently.

See :ref:`Chaining Analytics <Chaining Analytics>` for guidance on combining
analytics through direct and loose correlation.


Understand What the Detection Actually Claims
----------------------------------------------

A high-quality analytic should make a defensible claim about the behavior it
detects.

This is particularly important when mapping detection content to ATT&CK.
Identifying a tool that *can* perform a technique is not necessarily evidence
that the technique occurred, just as observing one implementation does not
necessarily establish coverage of every way the technique can be performed.

Before associating an analytic with an ATT&CK technique, ask whether the
observable evidence in the detection logic actually demonstrates the mapped
behavior.

See :ref:`Mapping Detections to ATT&CK <mapping-detections-to-attack>` for
guidance on creating and maintaining defensible ATT&CK mappings.


Design for Change
-----------------

Detections should be treated as maintained engineering artifacts rather than
one-time queries.

Adversary behavior evolves, ATT&CK changes, telemetry sources change, and
normal activity within an environment changes. Detection logic, mappings, and
exclusions should therefore be reviewed over time to ensure that they continue
to provide the intended visibility.

Changes in detection performance may also reveal opportunities to improve
telemetry, refine contextual logic, or address previously uncovered
implementations.

The :ref:`Detection Engineering Workflow <detection-engineering-workflow>`
provides a repeatable process for revisiting these decisions as detections and
environments evolve.
