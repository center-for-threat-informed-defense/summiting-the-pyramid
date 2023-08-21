Definitions
===========
This page provides key terms for the Summiting the Pyramid's research and methodology.

.. _Precision:

Precision
---------
**The ratio of true positives to total positive results given by an analytic** [#f1]_

Precision is extremely important when hunting for adversary activity. High precision analytics can most likely identify true malicious behavior. Precision corresponds to a low false positive rate within a detection environment. Precision can be more challenging to optimize for analytics higher on the pyramid.

.. figure:: _static/pyramid_of_pain.png
   :alt: Pyramid of Pain
   :align: center

   David Bianco's Pyramid of Pain [#f2]_

.. _Recall:

Recall
------
**Recall is the ratio of true positives to total relevant malicious events** [#f1]_

If recall is increased, more malicious behavior is identified. However, the defender is likely to have more false positives.

**How Precision and Recall Effect an Analytic**

.. figure:: _static/SmilesAndTriangles.png
   :alt: Precision and Recall Example
   :align: center

   Relationship between precision and recall for malicious events (red triangles) and benign events (happy faces) from MAD’s Threat Hunting Course [#f1]_

Recall and precision go hand-in-hand. This can be demonstrated in picture above, where the red triangles are malicious events, smiley faces are benign events, and the circle is the scope of an analytic. Increasing recall on an analytic might decrease precision since you are widening the scope of what needs to be collected. So if the circle is increased, you will get more red triangles, but you will also get more smiley faces. The precise malicious behavior might not be identified if recall is increased. 

On the other hand, increasing precision might decrease recall, since the scope of the activity detected by the more precise analytic narrows. If the circle gets smaller, it will detect the specific red triangles it’s after and lower the amount of green smiley faces. However, it might miss other related activity, since the circle is so small. It is important for defenders to find a balance between precision and recall that works for their environment and security needs.

.. _Observable:

Observable
----------
**An observable is an event, either benign or malicious, that is generated on a network or system and is visible to a defender.** [#f3]_

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

.. _Robustness:

Robustness
----------
**Robustness measures the effort needed by an adversary to evade an analytic**

Robustness is crucial for the effectiveness of an analytic, and is the focus of the Summiting the Pyramid project. Robustness is directly related to the cost required by an adversary to evade it, including time, resources, and money. High robustness indicates an adversary has to spend a lot to evade it, forcing them to operate at higher levels, such as interacting directly with the kernel. Therefore, robustness is equal to the level at which an adversary must operate to evade a defender’s detection.  

Analytic
--------
**An analytic is query logic used for detecting activity within different technology mediums using combinations of, or statistical analysis, of observables.**

In most security operations centers (SOCs), analytics are used to alert analysts on what they are concerned about within their environment, or keep track of certain behavior. For example, an analytic can be deployed by a team to send an alert when a new task is scheduled on a machine. Example analytics include CAR pseudocode, SIGMA rules, as well as the Splunk or Elastic queries generated by PySIGMA from SIGMA rules.

An analytic is made of different observables which create detection logic for an analytic. For example, an analytic looking for scheduled task creation could consist of observables such as the 4698 Task Creation Windows Event ID, the registry key path of the scheduled task, or the command line usage of the schtasks.exe tool. These observables can make an analytic more or less robust, based on how much effort an adversary would need to spend to evade it. For example, tracking the command line creation of task scheduling might be easier for an adversary to evade than tracking task scheduler event IDs, due to the fact that an adversary may not utilize the command line to schedule a task. Observables can be changed to create more robust analytics. 

.. _Analytic Robustness Categories:

Analytic Robustness Categories
------------------------------
**The five categories in the Summiting the Pyramid methodology group analytic robustness observables and analytics based on the Pyramid of Pain, refined to reflect difficulty and cost for an adversary to avoid triggering or being detected by them**

The Summiting the Pyramid methodology is focused on scoring analytics based on the difficulty for adversaries to evade them while still executing the Technique of interest, and without tampering with the defensive sensors. Different observables are more or less evadable than others. Summiting the Pyramid has defined five categories of observable robustness. The categories organize observables starting with the most easily evaded observables towards the bottom of the table, to the least easily evaded observables at the top of the table. To read more about how the categories are currently outlined, refer to our :ref:`Model Mapping Pages`.

.. _Sensor Robustness Categories:

Sensor Robustness Categories
----------------------------
**Columns in the Summiting the Pyramid methodology model group observables and events based on where they are generated, and therefore what an adversary would need to avoid triggering them while executing the same functionality.**

Analytics are constrained by the sensor data that is being used to log observables. The sensor robustness category columns look to create groups of sensor data observables based on how evasive they are in the OS. In this release, the generation locations are all different layers of the application and OS stack. In future releases, we may add locations elsewhere in cyber such as internet access point, or intra-enclave network traffic collection to extend this model to other types of observables. To read more about how the columns are currently outlined, refer to our :ref:`Model Mapping Pages`.

**References**

.. [#f1] https://www.cybrary.it/course/mitre-attack-threat-hunting/
.. [#f2] https://www.sans.org/tools/the-pyramid-of-pain/
.. [#f3] http://nist.gov/
.. [#f4] https://attack.mitre.org/datasources/