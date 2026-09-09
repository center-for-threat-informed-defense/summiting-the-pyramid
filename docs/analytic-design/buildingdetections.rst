Building High-Quality Detections
================================

High-quality detections do more than identify activity associated with an
adversary. They provide evidence that the behavior of interest is actually
occurring.

This requires choosing signals that are difficult for an adversary to avoid,
contain enough context to distinguish malicious from benign activity, and
meaningfully represent the behavior being detected. In practice, that means
focusing detection logic on observable system interactions rather than relying
too heavily on tools, disposable artifacts, or assumptions about what an
adversary *might* be doing.

Building detections this way improves both robustness and precision and
provides a stronger foundation for meaningful ATT&CK coverage.


Selecting High-Quality Signals
------------------------------

The signals used by an analytic determine both what it can detect and how
easily an adversary can evade it.

Highly specific indicators such as hashes, filenames, process names, or
command-line strings can be valuable, particularly when detecting known
activity. But these signals are often under adversary control and may disappear
with relatively inexpensive changes. The STP methodology therefore favors
signals tied to system interactions and behaviors that become increasingly
difficult for an adversary to avoid while still accomplishing their objective.

Signal selection should also consider precision. A system interaction may
be unavoidable for an adversary but occur frequently during legitimate
activity. In those cases, additional fields, conditions, or contextual signals
may be needed to distinguish the behavior of interest.

A useful signal therefore balances two questions:

* **How difficult is this signal for an adversary to avoid?**
* **How much context does it provide for distinguishing the behavior of
  interest?**

Whenever possible, detections should combine durable behavioral signals with
enough context to make them meaningful.


Detecting Behavior vs. Tools
----------------------------

Tools can provide useful detection opportunities, but detecting a tool is not
necessarily the same as detecting the behavior the tool can perform.

For example, an analytic may identify a particular executable, service name,
command string, or utility associated with an ATT&CK technique. That detection
may work very well for the known activity. But if the adversary can rename the
tool, use a different utility, modify the command, or accomplish the same
objective through another implementation, the behavior has not disappeared—the
observable has.

For detections intended to provide durable behavioral coverage, ask:

**What does the adversary have to cause the system to do in order to accomplish
this behavior?**

Detection logic built around those required system interactions is generally
more reusable across tools and implementations than logic tied exclusively to
the identity of a particular tool.

This does not mean tool- and indicator-based detections are inherently poor
detections. They can be extremely useful for known threats, hunting, and rapid
response. The important distinction is understanding what the analytic
actually detects and avoiding broader behavioral coverage claims than the
underlying logic supports.


Avoiding Inferred Intent
------------------------

Detection logic should distinguish between observing adversary behavior and
observing activity that *could be used* to perform adversary behavior.

Many legitimate tools and system functions can also be used maliciously.
Observing one of those tools does not, by itself, establish the attacker's
intent or demonstrate that a particular ATT&CK behavior occurred.

For example, reasoning that *"an adversary could use this utility to perform
Technique X, therefore detecting the utility detects Technique X"* relies on
inferred intent rather than direct evidence of the behavior. That may provide a
useful lead for threat hunting, but it is a weaker basis for claiming detection
coverage.

When evaluating detection logic, ask:

**What observable evidence demonstrates that the mapped behavior is actually
occurring?**

If establishing that relationship requires assumptions about what an adversary
*might* do next, additional context or detection logic may be necessary.

The goal is not to eliminate inference entirely. Detection engineering often
requires combining incomplete evidence. Rather, the goal is to make the
distinction between observed behavior and inferred intent explicit, and to
ensure coverage claims are supported by observable evidence.
