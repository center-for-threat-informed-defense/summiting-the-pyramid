.. _Application:

---------------------
Column A: Application
---------------------

**Description**: Observables associated with the use of applications available to defenders before adversary use and difficult for the adversary to modify.

The Application sensor robustness category groups observables which are collected closest to applications and are potentially modifiable by the user. For example, Windows provides developers the opportunity to create service providers for tools and applications, which can be used to create detection analytics. Other frameworks can be implemented by a user for needs within their environment. While users might need to download and configure application sensor data, they are available to the defender before an adversary conducts their attack.

.. note:: 
    Other efforts within the Center for Threat-Informed Defense are conducting research on sensor data generation, and will be expanding and adding sensor data to robustness categories in the future.

Observables
^^^^^^^^^^^
+-------------------------------+-----------------------------------------------------------------------+
| Category                      | Observables                                                           |
+===============================+=======================================================================+
| Scheduled Jobs                |  | Event ID 4698 (Task creation)                                      |
|                               |  | Event ID 4699 (Task deletion)                                      |
|                               |  | Event ID 4700 (Task enabled)                                       |
|                               |  | Event ID 4701 (Task disabled)                                      |
|                               |  | Event ID 4702 (Task updated)                                       |
+-------------------------------+-----------------------------------------------------------------------+
| MSI Installer                 |  | Event ID 1040 (Generic Service Resource Availability) [#f1]_       |
|                               |  | Event ID 1042 (Generic Service Resource Availability) [#f2]_       |
|                               |  | Event ID 1033 (Windows Installer Application Installation) [#f3]_  |
+-------------------------------+-----------------------------------------------------------------------+
| Windows Backup                |  | Event ID 524 (The System Catalog has been deleted) [#f4]_          |
+-------------------------------+-----------------------------------------------------------------------+

.. rubric:: References

.. [#f1] https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc773449%28v=ws.10%29
.. [#f2] https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc773487%28v=ws.10%29
.. [#f3] https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc735566%28v=ws.10%29
.. [#f4] https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc734301%28v=ws.10%29

* Roberto Rodriguez’s `API - To - Event <https://docs.google.com/spreadsheets/d/1Y3MHsgDWj_xH4qrqIMs4kYJq1FSuqv4LqIrcX24L10A/edit#gid=0>`_
* Jonny Johnson’s `TelemetrySource <https://docs.google.com/spreadsheets/d/1d7hPRktxzYWmYtfLFaU_vMBKX2z98bci0fssTYyofdo/edit#gid=0>`_
* UltimateWindowsSecurity `Event ID Glossary <https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx?i=j>`_