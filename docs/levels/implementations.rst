.. _Some Implementations:

--------------------------------------------------------
Level 4: Core to Some Implementations of (Sub-)Technique
--------------------------------------------------------

**Description**: Observables associated with low-variance behaviors of the (Sub-)Technique, unavoidable without a substantially different implementation

Analytics which are core to some implementations of a technique or sub-technique begin to look at the behaviors an adversary will demonstrate during an attack. These are defined as low variance behaviors, those which cannot be avoided by the implementation. Since these behaviors cannot be avoided, the artifacts they leave behind through observables will not change. Multiple implementations may point to the same low variance behavior, allowing a defender to create a robust analytic.

*Note*: These observables may change over time due to updates made to the ATT&CK Framework. 

Observables
^^^^^^^^^^^
+-------------------------------+-----------------------------------+------------------------------+
| Sub-Technique/Technique       | Observable Fields                 |   Observable Values          |
+===============================+===================================+==============================+
| Modify Authentication         |  AttributeLDAPDisplayName         | msDS-KeyCredentialLink       |
| Process (T1556)               |                                   |                              |
+-------------------------------+-----------------------------------+------------------------------+