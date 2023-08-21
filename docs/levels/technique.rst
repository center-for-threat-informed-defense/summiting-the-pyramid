.. _Technique:

-------------------------------------------
Level 5: Core to Sub-Technique or Technique
-------------------------------------------

**Description**: Observables associated with "chokepoints" or "invariant behaviors" of the (Sub-)Technique, unavoidable by any implementation

Some ATT&CK Techniques produce artifacts which are the same across all implementations of that behavior. These artifacts are considered invariant behaviors, which can be used to create robust analytics covering the whole of the specific Technique. While identifying these invariant behaviors requires research into all possible implementations of a technique and the observables which are produced, this provides the defender the most robust analytic option, as an adversary cannot evade the analytic unless they change their technique.

*Note*: These observables may change if the definition of the Technique is modified in a new version of ATT&CK. 

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
|  OS Credential Dumping:   |  TargetImage = lsass.exe                                 | The Splunk team outlines their       |
|  LSASS Memory (T1003.001) |  GrantedAccess: 0x1010 OR 0x1410                         | research for LSASS Dumping covers    | 
|                           |                                                          | multiple implementations of the      |
|                           |                                                          | technique [#f2]_                     |
+---------------------------+----------------------------------------------------------+--------------------------------------+


.. rubric:: References

.. [#f1] https://posts.specterops.io/abstracting-scheduled-tasks-3b6451f6a1c5
.. [#f2] https://www.splunk.com/en_us/blog/security/you-bet-your-lsass-hunting-lsass-access.html