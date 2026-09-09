Implementation Catalog
=======================

The catalog is derived from ATT&CK procedure examples and Atomic Red Team
tests. These sources are decomposed and normalized into reusable implementation
paths that capture the execution path and system interactions required to
perform the technique. A common system-interaction taxonomy provides a
consistent way to describe those behaviors and connect them to observable
telemetry.

The catalog therefore provides the behavioral baseline needed to ask a more
specific coverage question: *Which known ways of performing this technique can
our detections actually observe?*


How the Catalog Is Constructed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

ATT&CK and Atomic Red Team source material is analyzed to identify distinct
execution paths and the system interactions required by each path. Tool-,
actor-, and procedure-specific details are normalized where they do not
represent meaningful behavioral differences.

The resulting implementations preserve differences that matter for detection
while consolidating examples that represent the same underlying behavior.


ATT&CK Procedure Examples & Atomic Red Team Tests
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**ATT&CK procedure examples** provide real-world examples of how adversaries
have performed techniques, while **Atomic Red Team tests** provide concrete,
executable examples of technique behavior.

Using both sources provides a broader foundation for identifying practical
implementation paths. The source material is normalized into behavioral models
rather than treating every individual procedure or test as a distinct
implementation.


Behaviorally Distinct Implementation Paths
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Two procedures represent different implementations when they accomplish the
same ATT&CK technique through meaningfully different execution paths or
required system interactions.

This distinction matters because different paths may expose different detection
opportunities. A signal that exists on one path may disappear when the
adversary selects another, while some system interactions may be shared across
multiple implementations.


Required System Interactions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Each implementation is characterized by the system interactions required to
execute it.

Required interactions are particularly useful for detection engineering because
they shift the focus from *which tool the adversary used* to *what the
adversary had to cause the system to do*. Those interactions provide the
connection between an abstract ATT&CK behavior and the telemetry that can make
that behavior observable.


System-Interaction Taxonomy
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The **system-interaction taxonomy** provides a common vocabulary for
representing required system interactions consistently across implementations.

Using a shared taxonomy allows similar interactions to be recognized across
different techniques, tools, and procedures and creates a consistent basis for
connecting behavioral models to telemetry.


Connections to Telemetry & Sensor Fields
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

System interactions become useful for detection only when defenders have
telemetry capable of observing them.

Connecting implementation requirements to sensor and field-level mappings
helps identify where evidence of an implementation should appear and whether
the available telemetry contains enough information to detect it.

This also helps distinguish a **detection gap** from a **telemetry gap**:
sometimes better analytic logic can improve coverage, while in other cases the
necessary evidence simply is not available from the existing sensor.
