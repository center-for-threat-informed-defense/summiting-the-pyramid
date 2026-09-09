.. _field-level-telemetry-mappings:

Field-Level Telemetry Mappings & Scoring
========================================

Understanding which sensors can observe adversary behavior is an important
part of telemetry strategy, but sensor availability alone does not tell us
what information is actually available for detection.

Field-level telemetry mappings extend this analysis to the information
contained within individual events. By identifying the fields available from
supported telemetry sources, defenders can better understand what evidence is
available to detection logic and whether that evidence is sufficient to
observe the behavior of interest.



Why Field-Level Visibility Matters
----------------------------------

Detection logic operates on the information contained within telemetry—not
simply the presence of a sensor or event. An event may indicate that a class of system activity occurred while lacking
the information necessary to characterize the behavior more precisely.
Similarly, two analytics using the same event may rely on very different
fields and therefore provide very different detection value.

For example, identifying an Event ID alone may establish that an event
occurred, but the fields within that event often provide the context necessary
to determine what actually happened.



Standardizing Telemetry with OCSF
---------------------------------

Telemetry sources often use different schemas and field names to represent
similar information. Mapping fields to the **Open Cybersecurity Schema
Framework (OCSF)** provides a common representation for reasoning about
telemetry across different sources.

Standardization makes it easier to identify comparable information across
sensors and provides a foundation for extending field-level mappings as
additional telemetry sources are incorporated.


Field-Level Scoring
-------------------

Not all telemetry fields provide the same value for detection. Some observables are easily controlled or changed by an adversary, while
others reflect system interactions that are more difficult to avoid. Likewise,
some fields provide substantial context for distinguishing behavior, while
others provide relatively little information on their own.

Field-level scoring characterizes these differences so defenders can reason
about the relative value of the specific observables available within their
telemetry. These characteristics can then inform assessments of
:doc:`Detection Quality <detection-quality>`, including robustness and
precision. This approach also provides a more meaningful basis for comparing detections
that use the same telemetry source but rely on different fields or
combinations of evidence.


Identifying Telemetry Gaps
--------------------------

Field-level analysis can help distinguish between a problem with detection
logic and a limitation of the underlying telemetry. If the evidence needed to characterize a behavior exists in the available
telemetry but is not used by an analytic, improving the detection logic may
strengthen detection. If the necessary evidence is not captured by the sensor,
however, additional analytic logic cannot compensate for information that is
not available.

Recognizing this distinction can help defenders determine whether to improve
an analytic, enable additional fields or events, or introduce a different
telemetry source.


Putting Field-Level Telemetry to Use
------------------------------------

Field-level telemetry mappings and scoring can help defenders:

* understand what information their telemetry actually provides;
* identify the evidence available to observe specific system interactions;
* evaluate the relative value of different observable signals;
* determine whether existing telemetry can support a desired detection;
* identify where additional telemetry could improve detection; and
* make more informed decisions about telemetry collection and prioritization.

Field-level telemetry also provides an important foundation for other parts of
the Summiting the Pyramid methodology. It connects the behaviors and system
interactions represented through
:doc:`Implementation Coverage <implementation-coverage>` to observable
evidence, informs :doc:`Detection Quality <detection-quality>` assessment,
and can be used by tools such as the
:doc:`Detection Coverage Calculator <detection-coverage-calculator>` to
automate portions of that analysis.
