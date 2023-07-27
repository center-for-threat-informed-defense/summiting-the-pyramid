.. _Technique:

-------------------------------------------
Level 5: Core to Sub-Technique or Technique
-------------------------------------------

**Description**: Observables associated with "chokepoints" or "invariant behaviors" of the (Sub-)Technique, unavoidable by any implementation

Some ATT&CK Techniques produce artifacts which are the same across all implementations of that behavior. These artifacts are considered invariant behaviors, which can be used to create robust analytics covering the whole of the specific Technique. While identifying these invariant behaviors requires research into all possible implementations of a technique and the observables which are produced, this provides the defender the most robust analytic option, as an adversary cannot evade a specified technique unless they change their technique entirely.

*Note*: These observables may change over time due to updates made to the ATT&CK Framework. 

Observables
^^^^^^^^^^^
+-------------------------------+-------------------------------------------------------------+-------------------------------------+
| Sub-Technique/Technique       | Observables                                                 | Invariant Behavior                  |
+===============================+=============================================================+=====================================+
| Scheduled Tasks (T1053)       |  TargetObject = "HKLM\SOFTWARE\Microsoft\Windows NT\        | The registry key value is generated |
|                               |  CurrentVersion\Schedule\TaskCache\Tree" OR "HKLM\SOFTWARE\ | whenever a new task is created,     |
|                               |  Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache     | regardless of implementation [#f1]_ |
+-------------------------------+-------------------------------------------------------------+-------------------------------------+

.. rubric:: References

.. [#f1] https://posts.specterops.io/abstracting-scheduled-tasks-3b6451f6a1c5