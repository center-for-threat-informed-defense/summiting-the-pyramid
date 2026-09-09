.. _Technique:

Level 5: Invariant Behaviors / Core to Technique
================================================

**Description:** Observables associated with invariant behaviors or
behavioral chokepoints that all implementations of a technique or sub-technique
must exhibit.

Level 5 observables represent fundamental behaviors that cannot be avoided
without abandoning the technique altogether. They are shared across the known
implementation space and therefore provide the most robust detection
opportunities in the Summiting the Pyramid model. An invariant behavior is not simply an observable that appears frequently. It
is a behavior that is fundamentally required for accomplishing the technique.


Why are these observables placed at Level 5?
--------------------------------------------

Level 5 observables are behavioral chokepoints: points where different
implementations converge on an interaction that is fundamental to achieving
the technique. Because every implementation must exhibit the behavior, the adversary cannot
evade a Level 5 detection by changing tools, configuration, or implementation
strategy while still performing the same technique. To evade the detection, the adversary must instead **switch to an entirely
different ATT&CK technique**. Identifying invariant behaviors therefore provides the most robust detection
opportunities in the Summiting the Pyramid model.


Observables
-----------

The examples below illustrate invariant behaviors that occur across
implementations of a technique.

.. list-table::
   :header-rows: 1
   :widths: 30 35 35

   * - Technique / Sub-Technique
     - Observable
     - Invariant Behavior

   * - Scheduled Tasks (T1053)
     - ``TargetObject = HKLM\\SOFTWARE\\Microsoft\\Windows
       NT\\CurrentVersion\\Schedule\\TaskCache\\Tree`` or
       ``HKLM\\SOFTWARE\\Microsoft\\Windows
       NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks``
     - Creation of a scheduled task results in the Task Scheduler maintaining
       corresponding Registry data regardless of the implementation used to
       create the task.

   * - OS Credential Dumping: DCSync (T1003.006)
     - RPC endpoint/interface ``drsuapi`` with operations such as
       ``DRSReplicaSync`` or ``DRSGetNCChanges``
     - These operations represent the directory replication activity required
       by DCSync implementations using this mechanism.

.. rubric:: References

.. [#f1] https://posts.specterops.io/abstracting-scheduled-tasks-3b6451f6a1c5
.. [#f2] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47
.. [#f3] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/25c71d91-051f-4c26-977f-a70892f29b00 
.. [#f4] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/b63730ac-614c-431c-9501-28d6aca91894
