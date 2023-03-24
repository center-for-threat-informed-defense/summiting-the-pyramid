
AMSI Evasion - Grid Table
=========================

Note: This is the wall analogy aka higher is better

Original Analytic: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_delete/registry_delete_removal_amsi_registry_key.yml

Original Analytic Scoring
-------------------------
+-------------------------------------+--------------------------------------------+
| Level                               | Observables                                |
+=====================================+============================================+
| Kernel/Interfaces                   |                                            |
+-------------------------------------+--------------------------------------------+
| System Calls                        |                                            |
+-------------------------------------+--------------------------------------------+
| OS API                              |                                            |
+-------------------------------------+--------------------------------------------+
| Library API                         |                                            |
+-------------------------------------+--------------------------------------------+
| Native Tooling                      |                                            |
+-------------------------------------+--------------------------------------------+
| Custom Software/Open Source         |                                            |
+-------------------------------------+--------------------------------------------+
| Operational/Environmental Variables |EventType: DeleteKey<br/>                   |
|                                     |TargetObject|endswith:<br/>                 |
|                                     |- '{2781761E-28E0-4109-99FE-B9D127C57AFE}'  |
|                                     |- '{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}'  |
+-------------------------------------+--------------------------------------------+


Improved Analytic Scoring
-------------------------
+-------------------------------------+------------------------------------------------------------------------+
| Level                               | Observables                                                            |
+=====================================+========================================================================+
| Kernel/Interfaces                   |TargetObject|contains:<br/>                                             |
|                                     |- 'Computer\\HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\AMSI\\Providers\\'|
+-------------------------------------+------------------------------------------------------------------------+
| System Calls                        |                                                                        |
+-------------------------------------+------------------------------------------------------------------------+
| OS API                              |                                                                        |
+-------------------------------------+------------------------------------------------------------------------+
| Library API                         |                                                                        |
+-------------------------------------+------------------------------------------------------------------------+
| Native Tooling                      |                                                                        |
+-------------------------------------+------------------------------------------------------------------------+
| Custom Software/Open Source         |                                                                        |
+-------------------------------------+------------------------------------------------------------------------+
| Operational/Environmental Variables |                                                                        |
+-------------------------------------+------------------------------------------------------------------------+

Research Notes and Caveats
--------------------------
The original analytic relies on the adversary removing the AMSI provider from the registry. There is a known 
technique to evade this analytic where an new (Fake) AMSI is registered in the directory. This moves to detect 
any change in the directory. This directory is “special” due to the way the OS uses it in the queuing of AMSI 
tasking. With these modification the adversary cannot add, remove, or modify any values in this directory, 
detecting the activity.