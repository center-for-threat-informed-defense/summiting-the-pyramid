.. _User-Mode:

-------------------
Column U: User-Mode
-------------------

**Description**: Observables associated with user-mode OS activity.

The OS kernel (ring 0) is typically invoked using C wrapper functions running in user mode (ring 3). In Windows, these system wrapper functions usually start with Nt or Zw.
[#f1]_ .  In other operating systems, these C wrapper functions are usually included in libc. In either case, the wrapper functions switch into kernel mode using a predefined calling convention such as setting specific register flags and calling a certain interrupt. The attacker may bypass these wrapper functions by writing their own code to switch to kernel mode.

Observables
^^^^^^^^^^^
+-------------------------------+--------------------------------------------------------------------------------+
| Category                      | Observables                                                                    |
+===============================+================================================================================+
| Process                       | | Sysmon ID 5 (Process termination)                                            |
|                               | | Sysmon ID 10 (Process access)                                                |
|                               | | Event ID 7045 (New service installed)                                        |
+-------------------------------+--------------------------------------------------------------------------------+
| File                          | | Sysmon ID 2 (File creation time changed)                                     |
|                               | | Sysmon ID 11 (File create)                                                   |
|                               | | Sysmon ID 15 (File create stream hash)                                       |
|                               | | Sysmon ID 23 (File deletion)                                                 |
+-------------------------------+--------------------------------------------------------------------------------+
| Driver                        | | Sysmon ID 6 (Driver loaded)                                                  |
+-------------------------------+--------------------------------------------------------------------------------+
| Registry Key                  | | Sysmon ID 13 (Registry value set)                                            |
|                               | | Sysmon ID 14 (Registry object renamed)                                       |
+-------------------------------+--------------------------------------------------------------------------------+

**Useful resources:**

* Roberto Rodriguez’s `API - To - Event <https://docs.google.com/spreadsheets/d/1Y3MHsgDWj_xH4qrqIMs4kYJq1FSuqv4LqIrcX24L10A/edit#gid=0>`_
* Jonny Johnson’s `TelemetrySource <https://docs.google.com/spreadsheets/d/1d7hPRktxzYWmYtfLFaU_vMBKX2z98bci0fssTYyofdo/edit#gid=0>`_
* UltimateWindowsSecurity `Event ID Glossary <https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx?i=j>`_

.. rubric:: References

.. [#f1] https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-nt-and-zw-versions-of-the-native-system-services-routines
