.. _Some Implementations:

--------------------------------------------------------
Level 4: Core to Some Implementations of (Sub-)Technique
--------------------------------------------------------

**Description**: Observables associated with low-variance behaviors of the (sub-)technique, unavoidable without a substantially different implementation.

Analytics that are core to some implementations of a technique or sub-technique look at the behaviors an adversary will demonstrate during an attack. These behaviors are defined as low variance behaviors—those which cannot be avoided by the implementation. Multiple implementations may point to the same low variance behavior, allowing a defender to create a robust analytic.

.. note::

    These observables may change if the definition of the technique is modified in a
    new version of ATT&CK.

Observables
^^^^^^^^^^^
+-------------------------------+---------------------------------------------------+--------------------------------------+
| Sub-Technique/Technique       | Observables                                       | Low Variance Behavior                |
+===============================+===================================================+======================================+
| Modify Authentication         |  AttributeLDAPDisplayName: msDS-KeyCredentialLink | AttritubuteLDAPDisplayName is        |
| Process (T1556)               |                                                   | similar to a registry key, as it     |
|                               |                                                   | could be an arbitrary value or one of|
|                               |                                                   | several built-in "special" values.   |
|                               |                                                   | msDS-KeyCredentialLink is a special  |
|                               |                                                   | value used by the system for         |
|                               |                                                   | authentication. [#f1]_               |
+-------------------------------+---------------------------------------------------+--------------------------------------+
|  OS Credential Dumping:       |  TargetImage = lsass.exe                          | There are multiple access masks      |
|  LSASS Memory (T1003.001)     |  GrantedAccess: 0x1010 OR 0x1410                  | that can be used. This analytic      |
|                               |                                                   | covers two of those access masks.    |
|                               |                                                   | Anything that has the right bits     |
|                               |                                                   | is essentially a wildcard. [#f2]_    |
+-------------------------------+---------------------------------------------------+--------------------------------------+
| Scheduled Task/Job: At        | Event 5145: Relative Target Name = atsvc          | Remote access to the Windows At      |
| (T1053.002) - Remote          | Sysmon 18: PipeName = \atsvc                      | Service is achieved via the named    |
|                               | RPC Network Protocol                              | pipe "atsvc". [#f3]_                 |
|                               | - Endpoint: atsvc                                 |                                      |
|                               | - RPCOperation: NetrJobAdd                        |                                      |  
+-------------------------------+---------------------------------------------------+--------------------------------------+
| Modify Registry (T1112)       | Event 5145: Relative Target Name = winreg         | Remote access to the Windows Registry|
| Remote                        | Sysmon 18: PipeName = \winreg                     | is achieved via the named pipe       |
|                               | RPC Network Protocol                              | "winreg". [#f4]_                     |
|                               | - Endpoint: winreg                                |                                      |
|                               | - RPCOperation: BaseRegCreateKey OR               |                                      |  
|                               | BaseRegSetValue                                   |                                      | 
+-------------------------------+---------------------------------------------------+--------------------------------------+

.. rubric:: References:

.. [#f1] https://cyberstoph.org/posts/2022/03/detecting-shadow-credentials/
.. [#f2] https://www.splunk.com/en_us/blog/security/you-bet-your-lsass-hunting-lsass-access.html
.. [#f3] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931
.. [#f4] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/0fa3191d-bb79-490a-81bd-54c2601b7a78
