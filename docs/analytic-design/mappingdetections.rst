.. _mapping-detections-to-attack:

Mapping Detections to ATT&CK
============================

ATT&CK mappings provide a common language for describing what detection
content observes, but a mapping should represent a defensible relationship
between the detection logic and the adversary behavior described by the
technique.

An ATT&CK tag alone is not evidence of detection coverage. Before mapping an
analytic to a technique or sub-technique, examine the detection logic and ask:

* What behavior does this analytic actually observe?
* What evidence in the detection logic demonstrates that behavior?
* Does the analytic detect the behavior itself, or only a tool or artifact
  associated with it?
* Does the mapping depend on inferred attacker intent?
* Is the available telemetry sufficient to support the claimed behavior?

These questions help prevent several common mapping problems identified
through the STP research.

**Avoid overly broad mappings.** An analytic should not be mapped to every
technique a detected tool *could* potentially support. Adding mappings without
adding new detection capability increases apparent coverage without increasing
actual defensive capability.

**Map the observed behavior, not the possible behavior.** If an analytic
detects use of a utility but cannot determine what the utility is being used
to accomplish, the tool's potential capabilities should not automatically
determine the ATT&CK mapping.

**Use the most specific defensible mapping.** Where the detection logic
provides evidence of a particular sub-technique or behavior, prefer that
mapping over a broader or tangential association.

**Maintain mappings over time.** ATT&CK evolves as techniques and
sub-techniques are added, reorganized, and refined. Detection logic may remain
operationally useful while its metadata becomes outdated. If ATT&CK mappings
are used to assess coverage, maintaining those mappings is part of maintaining
the detection.

Ultimately, ATT&CK mappings are most useful when they describe what the
detection can demonstrate, rather than everything the observed activity might
plausibly enable.
