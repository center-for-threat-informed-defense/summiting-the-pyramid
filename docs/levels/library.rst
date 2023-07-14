.. _Library:

-----------------
Column L: Library
-----------------

**Description**: Observables associated with the use of libraries (including DLLs other than ntdll.DLL or other core OS libraries) available to defenders before adversary use and difficult for the adversary to modify.

The Library sensor robustness category groups observables which are collected closest to applications and are potentially modifiable by the user. For example, Windows provides developers the opportunity to create service providers for tools and applications, which can be used to create detection analytics. Other frameworks can be implemented by a user for needs within their environment. While users might need to download and configure library sensor data, they are available to the defender before an adversary conducts their attack.

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
