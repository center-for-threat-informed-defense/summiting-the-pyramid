Analytic Design & Engineering
===============================


.. toctree::
    :maxdepth: 1
    :caption: Contents

    detection-components
    robustdetection
    detection-diagram
    context
    chaining


How Do We Create Robust Detections?
-----------------------------------

A robust detection is one that is accurate and resistant to adversary evasion
over time. The Summiting Project provides various resources to help a defender
build robust detections, changing the game on the adversary:

* :ref:`Score Analytics for Resistance to Adversary Evasion:<scoring analytic>`
  Score your analytic observables against the Summiting host-based model or
  network traffic model to determine their resistance to adversary evasion over
  time and their impact on a detection's accuracy.
* :ref:`Robust Detection Guidance:<Build Robust Detection>` Combine the
  Summiting model scoring model with other concepts to build accurate
  detections. This includes building filters that are specific and difficult for
  adversaries to manipulate and combining those filters with additional
  detections for stronger confidence in malicious activity.
* :ref:`Analytic Repository:<analytics>` Use various examples of scored
  analytics against the Summiting scoring models, and how accuracy and
  resistance to adversary evasion over time can be improved.
* :ref:`Determine Malicious Intent through Context:<Context>` Determine the
  contextual requirements for developing analytics for an ambiguous technique in
  order to effectively focus on malicious behaviors and optimize robustness.


Assumptions and Caveats
-----------------------

The Summiting 2.0 project has the following scope and limitations:

* **Tampering is out of scope.** Adversaries may evade detection by tampering
  with data sources, but this project focuses on scenarios where the data source
  is trusted.
* **Tools and techniques change over time.** The analytic score might change as
  well. This goes for updates to the OS, pre-existing tools, changes to network
  infrastructure, and new adversary tool functionality, not just at Levels 4 and
  5.
* **Higher scoring analytics are harder to build.**  This is due to the level of
  research required for defenders to map the higher-level abstractions of TTPs
  into the lower level of observables, and it may not be within the realm of the
  defender's control (or data sources and detection tools) whether the requisite
  observables are contained within the network protocol header or the payload.
  In many cases, the intrinsic behavior of the operating system, service, or
  application dictates which observables are in the header and which observables
  are in the payload.
* **Not all networks are the same.** The research completed for accuracy
  attempts to translate generally the steps and considerations for building
  robust detections. However, not all networks are the same. Defenders should
  take stock of their own network and apply Summiting best practices based on
  their use case.
* **Not all network-based ATT&CK techniques are the same.** There are some
  network-based ATT&CK (sub-)techniques in which the adversary may control both
  endpoints involved in a network connection, which would be the case for
  tactics such as Command and Control and Data Exfiltration. There are also some
  (sub-)techniques in which the adversary controls only one endpoint involved in
  the connection, such as during the initial stages of remote Execution and
  Lateral Movement.
* **Analytic recommendations assume ideal data source and telemetry
  collection.** Developed analytics and the data sources that are used in them
  are directly tied to robustness for the detection of that technique. While
  other data sources may exist that can obtain the same information, it may have
  an adverse impact on robustness. Not all data sources are collected by default
  in all environments, and may or may not be feasible given operational and
  environmental constraints.
* **Ambiguous techniques are classified solely based on that technique's
  detection criteria.** The designation of a technique as ambiguous relies only
  on detection criteria related to that technique in isolation; combining
  multiple techniques to make a detection does not change it's original
  classification.
* **Other considerations.** There continues to be important properties of
  detections that have not been researched in-depth, such as the cost to
  engineer detections, the cost to collect corresponding data, the cost to run
  detections at scale, and so on.

