Definitions
===========

This page defines the key terms used throughout our research.

.. _Precision:

Precision
---------

**Precision is the fraction of relevant malicious events among all events matched by an
analytic.**

High precision analytics create fewer false positives. Precision is high at lower levels
of the pyramid (e.g. file hashes) but can be challenging for analytics higher on the
pyramid.

.. _Recall:

Recall
------

**Recall is the fraction of relevant malicious events that are detected by an analytic.**

High recall analytics are less likely to miss malicious activity. There is often a
tradeoff between precision and recall: as one increases, the other decreases. This
requires dialing in the right balance between minimizing missed detections while not
getting overwhelmed with false positives.

.. _Robustness:

Robustness
----------

**Robustness measures the effort needed by an adversary to evade an analytic.**

Robustness is crucial for the effectiveness of an analytic, and is the focus of the
Summiting the Pyramid project. Robustness is directly related to the cost required by an
adversary to evade it, including time, resources, and money. High robustness indicates
an adversary has to spend a lot to evade it, forcing them to operate at higher levels,
such as interacting directly with the kernel. Therefore, robustness is equal to the
level at which an adversary must operate to evade a defender’s detection.

.. _Observable:

Observable
----------

**An observable is an event, either benign or malicious, that is generated on a network
or system and is visible to a defender.**

Example observables include:

+-------------------------------+--------------------------------------------------------------------------------------+
| Observable                    | Generating Activity                                                                  |
+===============================+======================================================================================+
| Windows Event 4688            |  Windows Kernel function monitored by ETW (e.g. PspCreateProcess) creates a process  |
+-------------------------------+--------------------------------------------------------------------------------------+
| Windows Event 4688 Image "foo"|  Windows Kernel function monitored by ETW creates a process with filename "foo"      |
+-------------------------------+--------------------------------------------------------------------------------------+
| Sysmon Event 1                | Windows function monitored by PsSetCreateProcessNotifyRoutine (e.g. CreateProcess)   |
| OriginalFilename="foo"        | creates a process from a source file with "foo" filename in PE Header                |
+-------------------------------+--------------------------------------------------------------------------------------+
| .pcap File                    | Network traffic occurs, visible to a packet analyzer                                 |
+-------------------------------+--------------------------------------------------------------------------------------+
| Zeek alert                    | Network traffic occurs, visible to Zeek, which matches a policy                      |
+-------------------------------+--------------------------------------------------------------------------------------+

Analytic
--------

**An analytic is query logic used for detecting activity within a technology stack based
on one more observables.**

In most security operations centers (SOCs), analytics are used to alert analysts to
concerning behavior in their environment. For example, an analytic can be deployed by a
team to send an alert when a new task is scheduled on a machine. Example analytics
include CAR pseudocode, SIGMA rules, as well as the Splunk or Elastic queries generated
by PySIGMA from SIGMA rules.

An analytic is made of different observables which create detection logic for an
analytic. For example, an analytic looking for scheduled task creation could consist of
observables such as the 4698 Task Creation Windows Event ID, the registry key path of
the scheduled task, or the command line usage of the schtasks.exe tool. These
observables can make an analytic more or less robust, based on how much effort an
adversary would expend to evade it. For example, tracking the command line creation of
task scheduling might be easier for an adversary to evade than tracking task scheduler
event IDs, due to the fact that an adversary may not utilize the command line to
schedule a task. Observables can be changed to create more robust analytics.

.. _Analytic Robustness Categories:

Analytic Robustness Categories
------------------------------

**The five levels in the methodology represent increasing cost or difficulty for the
adversary to avoid producing those observables.**

Different observables are more or less evadable than others. Summiting the Pyramid has
defined five categories of observable robustness. The categories organize observables
starting with the most easily evaded observables at the bottom of the table, to the
least easily evaded observables at the top of the table.

.. _Event Robustness Categories:

Event Robustness Categories
---------------------------

**The three columns in the methodology represent increasing cost or difficulty for the
adversary to avoid those sensors.**

Analytics are constrained by the sensor data that is being used to log observables. The
event robustness category columns look to create groups of event data observables based
on how evasive they are in the OS. In this release, the generation locations are all
different layers of the application and OS stack. Future releases will build on this to
model different kinds of observability on other operating systems, on networks, etc.
