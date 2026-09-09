Building High-Quality Detections
================================

High-quality detections do more than identify activity associated with an
adversary. They provide meaningful evidence that the behavior of interest is
actually occurring while remaining difficult for an adversary to evade.

Building detections this way requires considering both the signals used by the
analytic and the context those signals provide. In practice, this means
focusing detection logic on observable system interactions rather than relying
too heavily on tools, disposable artifacts, or assumptions about what an
adversary *might* be doing.

The goal is to improve :ref:`Detection Quality <detection-quality>` while
building a stronger foundation for meaningful ATT&CK coverage.


Detection Quality as a Design Goal
----------------------------------

Detection Quality considers two complementary characteristics of detection
logic: robustness and precision.

A detection may perform well in one dimension without performing well in the
other. A highly specific indicator may provide strong evidence of known
malicious activity but be easy for an adversary to change. Conversely, an
observable tied to a system interaction that an adversary cannot easily avoid
may also occur frequently during legitimate activity.

The goal is therefore not simply to maximize one characteristic. Detection
engineers should select and combine signals that provide durable visibility
while also supplying enough context to distinguish the behavior of interest.

For a more detailed discussion of these characteristics and how they are
evaluated, see :ref:`Detection Quality <detection-quality>`.


Selecting High-Quality Signals
------------------------------

The signals used by an analytic determine both what it can detect and how
easily an adversary can evade it.

Highly specific indicators such as hashes, filenames, process names, or
command-line strings can be valuable, particularly when detecting known
activity. However, these signals are often under adversary control and may
disappear with relatively inexpensive changes.

For detections intended to provide durable coverage, favor signals tied to
system interactions and behaviors that become increasingly difficult for an
adversary to avoid while still accomplishing their objective.

Signal selection should also account for the context an observable provides.
A system interaction may be unavoidable for an adversary but occur frequently
during legitimate activity. In those cases, additional fields, conditions, or
contextual signals may be needed to distinguish the behavior of interest.

A useful signal therefore balances two questions:

* How difficult is this signal for an adversary to avoid?
* How much context does it provide for distinguishing the behavior of interest?

Whenever possible, combine durable behavioral signals with enough context to
make the resulting detection meaningful.

The :ref:`Detection Decomposition Diagram (D3) <detection-decomposition-diagram>`
can help identify useful observables across different implementations of a
technique, while :ref:`Field-Level Telemetry Mappings
<field-level-telemetry-mappings>` can help determine what evidence is available
within the underlying telemetry.


Detecting Behavior vs. Tools
----------------------------

Tools can provide useful detection opportunities, but detecting a tool is not
necessarily the same as detecting the behavior the tool can perform.

An analytic may identify a particular executable, service name, command
string, or utility associated with an ATT&CK technique. That detection may
work very well for the known activity. But if the adversary can rename the
tool, use a different utility, modify the command, or accomplish the same
objective through another implementation, the behavior has not disappeared—the
observable has.

For detections intended to provide durable behavioral coverage, ask:

**What does the adversary have to cause the system to do in order to accomplish
this behavior?**

Detection logic built around required system interactions is generally more
reusable across tools and implementations than logic tied exclusively to the
identity of a particular tool.

This does not mean tool- and indicator-based detections are inherently poor
detections. They can be valuable for known threats, threat hunting, and rapid
response. The important distinction is understanding what the analytic
actually detects and avoiding broader behavioral coverage claims than the
underlying logic supports.

For more information on how different behavioral paths affect coverage, see
:ref:`Implementation Coverage <implementation-coverage>`.


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

If establishing that relationship requires assumptions about what an adversary
*might* be doing or what they *might* do next, additional context or detection
logic may be necessary.

This does not mean inference has no place in detection engineering. In many
cases, no single observable can establish malicious intent on its own.
Additional technique-level, chain-level, or environmental context can help
distinguish malicious behavior from legitimate activity.

See :ref:`Using Context to Determine Intent <using-context-to-determine-intent>`
for guidance on identifying and incorporating that context.


Designing for the Environment
-----------------------------

High-quality detection logic must also account for the environment in which it
will operate.

Behavior that is unusual in one environment may be routine in another.
Environmental baselines, known benign activity, user roles, system functions,
and organizational policies can all provide context for distinguishing
malicious from legitimate behavior.

Exclusions and filters can reduce known benign activity, but they should be
introduced carefully. Broad exclusions can create blind spots that an
adversary may be able to exploit. Where exclusions are necessary, favor
specific conditions grounded in known benign behavior and consider how easily
an adversary could satisfy those conditions.

Detection logic should also be tested against representative data and reviewed
over time as the environment and adversary behavior change.


When a Single Analytic Is Not Enough
------------------------------------

Some behaviors cannot be reliably distinguished as malicious based on a single
observable or analytic.

In these cases, combining related observations can provide the additional
context needed to make a stronger determination. For example, individually
common discovery activities may become more significant when several occur
for the same user or system within a relevant period of time.

Correlation should be used when the combined evidence provides information
that the individual analytics cannot provide on their own—not simply to make
an analytic more complex.

See :ref:`Chaining Analytics <chaining-analytics>` for guidance on direct and
loose correlation approaches.


From Design to Evaluation
-------------------------

Building a high-quality detection is an iterative process. Detection engineers
should understand the behavior they want to observe, select useful telemetry
and signals, add context where necessary, test the resulting analytic, and
refine it as conditions change.

Once an analytic has been developed, its quality and coverage can be evaluated
using the broader Summiting the Pyramid methodology.

See :ref:`Measuring Detection Coverage <measuring-detection-coverage>` for
guidance on evaluating Detection Quality and Implementation Coverage, and
:ref:`Mapping Detections to ATT&CK <mapping-detections-to-attack>` for guidance
on ensuring that ATT&CK mappings accurately represent what the detection logic
can demonstrate.
