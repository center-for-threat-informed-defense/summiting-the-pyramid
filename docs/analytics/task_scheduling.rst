-------------------------
Task Scheduling
-------------------------

..
    Insert link to analytic here (like a Sigma rule)
- https://car.mitre.org/analytics/CAR-2013-08-001/
- https://car.mitre.org/analytics/CAR-2013-05-004/
- https://github.com/splunk/security_content/blob/develop/detections/endpoint/scheduled_task_creation_on_remote_endpoint_using_at.yml
- https://github.com/splunk/security_content/blob/develop/detections/endpoint/scheduled_task_initiation_on_remote_endpoint.yml


.. list-table::
    :widths: 30 70

    * - Original Analytic
      -  | Image: (schtasks.exe | at.exe) AND 
         | CommandLine: (“*\\\\*” | “*/s” | “*/run")
    * - Improved Analytic #1
      - | index:Sysmon EventID:(12 | 13 | 14) AND
        | TargetObject:  (“HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\*” | “HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\*”)
    * - Improved Analytic #2
      - | EventID: (4656 | 4657 | 4663) AND
        | TargetObject:  (“HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\*” | “HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\*”)

Original Analytic Scoring
^^^^^^^^^^^^^^^^^^^^^^^^^
.. list-table::
    :widths: 15 30 60
    :header-rows: 1

    * - Level
      - Level Name
      - Observables
    * - 7
      - Kernel/Interfaces
      - 
    * - 6
      - System Calls
      - 
    * - 5
      - OS API
      - 
    * - 4
      - Library API
      - 
    * - 3
      - Tools Outside Adversary Control
      - Image: (schtasks.exe | at.exe)
    * - 2
      - Tools Within Adversary Control
      - 
    * - 1
      - Operational/Environmental Variables
      - CommandLine: (“*\\\\*” | “*/s” | “*/run")


Improved Analytic Scoring #1
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
    :widths: 15 30 60
    :header-rows: 1

    * - Level
      - Level Name
      - Observables
    * - 7
      - Kernel/Interfaces
      - 
    * - 6
      - System Calls
      - 
    * - 5
      - OS API
      - | index:Sysmon EventID:(12 | 13 | 14) AND
        | TargetObject:  (“HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\*” | “HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\*”)
    * - 4
      - Library API
      - 
    * - 3
      - Tools Outside Adversary Control
      - 
    * - 2
      - Tools Within Adversary Control
      - 
    * - 1
      - Operational/Environmental Variables
      - 

The original analytics, and many other detections related to scheduled tasks, look at process name and 
combinations of commandline arguments related remote task scheduling, unusual task names, suspicious 
usernames, etc. These observables are at the Operational/Environmental Variables level and can be easily changed by
an attacker to avoid detection. The scheduled task capability abstraction from SpecterOps highlights that 
registry key creation/modification occurs for several implementations of local and remote task scheduling [#f1]_. 
This improved detection is more difficult for an adversary to evade, and according to the StP methodology 
is a level 5.


Improved Analytic Scoring #2
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
    :widths: 15 30 60
    :header-rows: 1

    * - Level
      - Level Name
      - Observables
    * - 7
      - Kernel/Interfaces
      - | EventID: (4656 | 4657 | 4663) AND
        | TargetObject:  (“HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\*” | “HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\*”)
    * - 6
      - System Calls
      - 
    * - 5
      - OS API
      - 
    * - 4
      - Library API
      - 
    * - 3
      - Tools Outside Adversary Control
      - 
    * - 2
      - Tools Within Adversary Control
      - 
    * - 1
      - Operational/Environmental Variables
      -

This second improved analytic implementation is looking for the same invariant behavior but uses a different data source 
that can detect activity at a deeper level in the OS than Sysmon. According to related research from Roberto 
Rodriguez, Windows Event ID 4656, 4657, and 4663 can fire in response to several kernel-level API calls related 
to accessing or setting registry keys [#f2]_.

+---------------------+---------+-----------------------------------------+-------------------------------------+--------------------+
| API Call            | EventID | Event Name                              | Log Provider                        | ATT&CK Data Source |
+=====================+=========+=========================================+=====================================+====================+
| ZwOpenKey           | 4656    | A handle to an object was requested     | Microsoft-Windows-Security-Auditing | Windows Registry   |
+---------------------+---------+-----------------------------------------+-------------------------------------+--------------------+
| ZwSetValueKey       | 4657    | A registry value was modified           | Microsoft-Windows-Security-Auditing | Windows Registry   |
+---------------------+---------+-----------------------------------------+-------------------------------------+--------------------+
| ZwEnumerateKey      | 4663    | An attempt was made to access an object | Microsoft-Windows-Security-Auditing | Windows Registry   |
+---------------------+---------+-----------------------------------------+-------------------------------------+--------------------+
| ZwEnumerateValueKey | 4663    | An attempt was made to access an object | Microsoft-Windows-Security-Auditing | Windows Registry   |
+---------------------+---------+-----------------------------------------+-------------------------------------+--------------------+
| ZwOpenKey           | 4663    | An attempt was made to access an object | Microsoft-Windows-Security-Auditing | Windows Registry   |
+---------------------+---------+-----------------------------------------+-------------------------------------+--------------------+
| ZwSetValueKey       | 4663    | An attempt was made to access an object | Microsoft-Windows-Security-Auditing | Windows Registry   |
+---------------------+---------+-----------------------------------------+-------------------------------------+--------------------+

Research Notes and Caveats
^^^^^^^^^^^^^^^^^^^^^^^^^^
The main caveat here is that these event IDs will only be generated if a SACL is configured on the respective registry keys, 
which in this case are ``HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*`` 
and ``HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\*``. With the SACL applied, 
the improved analytic scores at a 7 according to the Summiting the Pyramid methodology and is very challenging for an 
adversary to evade.

.. rubric:: References

.. [#f1] https://posts.specterops.io/abstracting-scheduled-tasks-3b6451f6a1c5
.. [#f2] https://docs.google.com/spreadsheets/d/1Y3MHsgDWj_xH4qrqIMs4kYJq1FSuqv4LqIrcX24L10A/edit#gid=0
