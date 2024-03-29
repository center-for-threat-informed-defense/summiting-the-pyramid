.. _Technique:

-------------------------------------------
Level 5: Core to Sub-Technique or Technique
-------------------------------------------

    **Description**: Observables associated with "chokepoints" or "invariant behaviors" of
    the (Sub-)Technique, unavoidable by any implementation

Some ATT&CK Techniques produce artifacts which are the same across all implementations
of that behavior. These artifacts are considered invariant behaviors, i.e. an essential
part of any implementation of the behavior. While identifying these invariant behaviors
requires research into all possible implementations of a technique and the observables
which are produced, this provides the defender the most robust analytic option, as it
forces the adversary to switch to an entirely different technique.

.. note::

    These observables may change if the definition of the technique is modified in a
    new version of ATT&CK.

Observables
^^^^^^^^^^^
+---------------------------+----------------------------------------------------------+--------------------------------------+
| Sub-Technique/Technique   | Observables                                              | Invariant Behavior                   |
+===========================+==========================================================+======================================+
|  Scheduled Tasks (T1053)  |  TargetObject = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\ |  The registry key value is generated |
|                           |  CurrentVersion\\Schedule\\TaskCache\\Tree" OR "HKLM\\   |  whenever a new task is created,     |
|                           |  SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\       |  regardless of implementation [#f1]_ |
|                           |  Schedule\\TaskCache"                                    |                                      |
+---------------------------+----------------------------------------------------------+--------------------------------------+


.. rubric:: References

.. [#f1] https://posts.specterops.io/abstracting-scheduled-tasks-3b6451f6a1c5
