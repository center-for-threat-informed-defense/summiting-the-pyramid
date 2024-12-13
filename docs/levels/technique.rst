.. _Technique:

-------------------------------------------
Level 5: Core to Sub-Technique or Technique
-------------------------------------------

**Description**: Observables associated with “chokepoints” or “invariant behaviors” of the (sub-)technique, unavoidable by any implementation.

Some ATT&CK techniques produce artifacts that are the same across all implementations of that behavior. These artifacts are considered invariant behaviors, i.e., an essential part of any implementation of the behavior. While identifying these invariant behaviors requires research into all possible implementations of a technique and the observables that are produced, it provides the defender the most robust analytic option, as it forces the adversary to switch to an entirely different technique.

.. note::

    These observables may change if the definition of the technique is modified in a
    new version of ATT&CK.

Observables
^^^^^^^^^^^
+---------------------------+----------------------------------------------------------+---------------------------------------+
| Sub-Technique/Technique   | Observables                                              | Invariant Behavior                    |
+===========================+==========================================================+=======================================+
|  Scheduled Tasks (T1053)  |  TargetObject = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\ |  The registry key value is generated  |
|                           |  CurrentVersion\\Schedule\\TaskCache\\Tree" OR "HKLM\\   |  whenever a new task is created,      |
|                           |  SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\       |  regardless of implementation. [#f1]_ |
|                           |  Schedule\\TaskCache"                                    |                                       |
+---------------------------+----------------------------------------------------------+---------------------------------------+
|  OS Credential Dumping:   |  RPC Network Protocol                                    | DRSReplicaSync triggers replication   |
|  DCSync (T1003.006)       |  - Endpoint (aka, Interface) = drsuapi [#f2]_            | from another Domain Controller. [#f3]_|
|                           |  - Operation (aka, Method) = DRSReplicaSync OR           | DRSGetNCChanges replicates updates    |
|                           |  DRSGetNCChanges                                         | from a naming context (NC) on another |
|                           |                                                          | server. [#f4]_                        | 
+---------------------------+----------------------------------------------------------+---------------------------------------+

.. rubric:: References

.. [#f1] https://posts.specterops.io/abstracting-scheduled-tasks-3b6451f6a1c5
.. [#f2] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47
.. [#f3] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/25c71d91-051f-4c26-977f-a70892f29b00 
.. [#f4] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/b63730ac-614c-431c-9501-28d6aca91894
