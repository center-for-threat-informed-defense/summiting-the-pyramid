.. _Some Implementations:

--------------------------------------------------------
Level 4: Core to Some Implementations of (Sub-)Technique
--------------------------------------------------------

**Description**: Observables associated with low-variance behaviors of the (Sub-)Technique, unavoidable without a substantially different implementation

Analytics which are core to some implementations of a technique or sub-technique look at the behaviors an adversary will demonstrate during an attack. These are defined as low variance behaviors, those which cannot be avoided by the implementation. Multiple implementations may point to the same low variance behavior, allowing a defender to create a robust analytic.

*Note*: These observables may change if the definition of the Technique is modified in a new version of ATT&CK.

Observables
^^^^^^^^^^^
+-------------------------------+---------------------------------------------------+------------------------------------+
| Sub-Technique/Technique       | Observables                                       | Low Variance Behavior              |
+===============================+===================================================+====================================+
| Modify Authentication         |  AttributeLDAPDisplayName: msDS-KeyCredentialLink | AttritubuteLDAPDisplayName is      |
| Process (T1556)               |                                                   | similar to a registry key, as it   |
|                               |                                                   | could be an arbitrary value or one |
|                               |                                                   | several built-in "special" values. |
|                               |                                                   | mdDS-KeyCredentialLink is a special|
|                               |                                                   | value used by the system for       |
|                               |                                                   | authentication [#f1]_              |
+-------------------------------+---------------------------------------------------+------------------------------------+
| Indicator Removal: File       | Event ID 524                                      | While this is a event robustness   |
| Deletion (T1070.004)          | Provider Name: Microsoft-Windows-Backup           | category, the utilization of this  |
|                               |                                                   | event is indicative of this        |
|                               |                                                   | technique.                         |
+-------------------------------+---------------------------------------------------+------------------------------------+

.. rubric:: References:

.. [#f1] https://cyberstoph.org/posts/2022/03/detecting-shadow-credentials/