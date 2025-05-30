Definitions
===========

This page defines the key terms used throughout our research.

.. _Detection:

Detection
---------

**A detection is the identification of malicious activity within one's
environment.** [#f1]_

Detection is the core of threat hunting activities. An analyst can create
detection rules based on the malicious activity they want to be alerted on and
can update these rules as necessary. Detection logic feeds into the creation of
an analytic query.

.. _Accuracy:

Accuracy
--------

**An accurate detection is one that has low false positives and low false
negatives.** [#f2]_

The definition of accurate combines traditional detection metrics precision and
recall. A precise detection is one that has a low probability of alerting on
benign activity. A detection with high recall is one that has a high probability
of detecting malicious events. A highly accurate detection will encompass high
precision and recall rates.

.. _Robust Detection:

Robust Detection
----------------

**A robust detection is one that has high accuracy and is resistant to adversary
evasion over time.**

Examples of how to analyze robust detections include the following:

* A hash can provide a low false positive rate, but is not highly accurate to
  false negatives or resistant to evasion over time.
* A registry key created when scheduling a task is accurate and resistant to
  evasion over time, but can have a high false positive rate due to benign
  behavior.
* Detecting LSASS dumping through GrantedAccess masks and the target image
  lsass.exe is highly accurate. It can also be made resistant to adversary
  evasion over time based on the observables used.

.. _Observable:

Observable
----------

**An observable is an event, either benign or malicious, that is generated on a
network or system and is visible to a defender.**

Example observables include:

+-------------------------------+--------------------------------------------------------------------------------------+
| Observable                    | Generating Activity                                                                  |
+===============================+======================================================================================+
| Windows Event 4688            |  Windows Kernel function monitored by ETW (e.g., PspCreateProcess) creates a process |
+-------------------------------+--------------------------------------------------------------------------------------+
| Windows Event 4688 Image "foo"|  Windows Kernel function monitored by ETW creates a process with filename “foo”      |
+-------------------------------+--------------------------------------------------------------------------------------+
| Sysmon Event 1                | Windows function monitored by PsSetCreateProcessNotifyRoutine (e.g., CreateProcess)  |
| OriginalFilename="foo"        | creates a process from a source file with "foo" filename in PE Header                |
+-------------------------------+--------------------------------------------------------------------------------------+
| .pcap File                    | Network traffic occurs, visible to a packet analyzer                                 |
+-------------------------------+--------------------------------------------------------------------------------------+
| Zeek alert                    | Network traffic occurs, visible to Zeek, which matches a policy                      |
+-------------------------------+--------------------------------------------------------------------------------------+

Detection Analytic
------------------

**An detection analytic is query logic used for detecting activity within a
technology stack based on one or more observables.**

In most security operations centers (SOCs), analytics are used to alert analysts
to concerning behavior in their environment. For example, an analytic can be
deployed by a team to send an alert when a new task is scheduled on a machine.
Example analytics include CAR pseudocode, Sigma rules, and the Splunk or Elastic
queries generated by PySigma from Sigma rules.

An analytic is made of different observables that create detection logic for the
analytic. For example, an analytic looking for scheduled task creation could
consist of observables such as the 4698 Task Creation Windows Event ID, the
registry key path of the scheduled task, or the command-line usage of the
schtasks.exe tool. These observables can make an analytic score higher on the
Summiting model based on how much effort an adversary would expend to evade it.
For example, tracking the command-line creation of task scheduling might be
easier for an adversary to evade than tracking task scheduler event IDs, because
an adversary may not utilize the command line to schedule a task. Observables
can be changed to create more robust detections.

.. _Analytic Robustness Categories:

Analytic Robustness Categories
------------------------------

**The five levels in the methodology represent increasing cost or difficulty for
the adversary to avoid producing those observables.**

Different observables are more or less difficult to evade than others. Summiting
the Pyramid has defined five categories of observable robustness. The categories
organize observables starting with the most easily evaded observables at the
bottom of the table, to the least easily evaded observables at the top of the
table.

.. _Host-Based Event Robustness Categories:

Event Robustness Categories
---------------------------

**The three columns in the methodology represent increasing cost or difficulty
for the adversary to avoid host-based sensors.**

Detections are constrained by the sensor data being used to log observables. The
event robustness category columns look to create groups of event data
observables based on how evasive they are in the OS. In this release, the
generation locations are all different layers of the application and OS stack.
Future releases will build on these columns to model different kinds of
observability on other operating systems, on networks, and so on.

.. _Network Traffic Robustness Categories:

Network Traffic Robustness Categories
-------------------------------------

**Detections are constrained by the observables in the network traffic log, and
the observables are dependent on the sensor's visibility into the relevant
network protocol.**

The event robustness category columns look to create groups of event data
observables based on how evasive they are within the relevant network protocol.
In this release, two groups are defined: protocol header and protocol payload.
This is a simple, yet flexible model that can be applied to any network
protocol. For example, if the adversary's activity occurs via the Hypertext
Transfer Protocol (HTTP) protocol (OSI Layer 7), then the relevant observables
would be grouped as either HTTP protocol header or HTTP protocol payload.
Similarly, if the adversary's activity occurs via the ICMP protocol (OSI Layer
3), then the relevant observables would be grouped as either ICMP protocol
header or ICMP protocol payload. By simply using the labels Protocol Header and
Protocol Payload, these event robustness categories can be applied easily to any
protocol. Future releases could expand these categories, if needed.

.. _Originator Endpoint:

Originator Endpoint
-------------------

**The originator endpoint is the device that originates the network connection
or attack.**

The originator endpoint is the device that initiates the relevant activity and
the associated network connection. This term is adopted from Zeek documentation
to describe the roles of each endpoint in a network connection.

According to Zeek, “the context of a connection between an originator and a
responder ... differ from packet-level concepts of source and destination, as
well as from higher-level abstractions such as client and server … when
establishing the connection state, with the sender of the initial packet
becoming the originator and the recipient becoming the responder.” [#f3]_

.. _Responder Endpoint:

Responder Endpoint
------------------

**A responder endpoint is the device that is the target of the network
connection or attack.**

The responder endpoint is the device that is the target of the relevant activity
and receives the associated network connection. This term is adopted from Zeek
documentation to describe the roles of each endpoint in a network connection.
[#f3]_


.. _Intent Definition:

Intent
------------------

**Intent is the the cyber actor's disposition when performing certain actions or
behaviors within an environment**

Malicious intent refers to the purposeful pursuit of unauthorized objectives
within a system or network, typically for personal, political, or strategic
gain. This includes actions aimed at disrupting, degrading, surveilling,
exploiting, or extracting information from systems, regardless of whether
immediate harm is inflicted. 

Conversely, benign intent is the attributed belief that an actor is operating
without those stated goals in mind.

.. _Context Definition:

Context
------------------

**Context is the circumstances surrounding the behavior or activity of
interest.**

Context serves to substantiate, clarify, and illuminate observed activity or
behavior. Context can be derived from observable data or from activities that
are directly, or indirectly, related to the target behavior. These are behaviors
that occur before, after, or concurrently with the technique of interest,
providing additional insights into the broader activity.


.. _AT Definition:

Ambiguous Technique
-------------------

**An ambiguous technique is a technique whose observables are not sufficient to
determine intent with a preponderance of certainty.**

An ambiguous technique is a technique which has observables and key behaviors
that can originate with either benign or malicious intent, and thus more
deliberate and conclusive detections must be enacted in order to reduce
potentially significant false positives.

.. rubric:: References

.. [#f1] https://www.mitre.org/sites/default/files/2021-11/prs-19-3892-ttp-based-hunting.pdf
.. [#f2] https://www.sciencedirect.com/topics/engineering/classification-accuracy
.. [#f3] https://docs.zeek.org/en/current/scripting/basics.html#writing-scripts-connection-record
