.. _OS API Level:

---------------------------
Level 5: OS (SubSystem) API
---------------------------

**Description**: Defined by managed code and can be used individually to accomplish adversary objectives.

API calls, as defined by Microsoft, can be used to, “perform tasks when it is difficult to write equivalent procedures of your own.” [#f1]_ These functions 
are defined by the packages downloaded by the user or the system, such as DLLs and COM Methods, and can be managed or unmanaged. API calls allow the user 
to direct commands to the computer system, such as logging on a user (``LogonUser``), identifying errors on a thread (GetLastError), and others related to user 
interfaces, shell environment, and system services. It allows an adversary flexibility in utilizing different computer functions to manipulate computer systems 
towards their goals. However, it is limiting since these API calls are defined by the operating system. This level will be explicitly for the Windows OS, 
since other operating systems will interact directly with the kernel through system calls.

**Why should we track API calls?**

API calls [#f2]_ allow a defender to focus on the certain capability of a tool compared to the tool itself. This potentially allows the creation of analytics that track 
similar behavior of API calls, called low-variance behaviors, across multiple different tools, rather than building an analytic per tool. Now, certain API 
calls might hook specific events. Jonny Johnson’s research focuses on mapping API calls to Windows Event IDs and Sysmon Event IDs that they may trigger [#f3]_ [#f4]_. 
For example, ``LogonUserA`` will trigger Event ID 4624. However, this is not true for all events. Monitoring API calls can be extremely difficult. However, 
further static and dynamic research can uncover potential links to event codes, or lower-level calls that can be tracked otherwise.

**Examples**: API calls

Observables
^^^^^^^^^^^
+-------------------------------+-----------------------------------+-------------------------------------+
| Category                      | Observable Fields                 |   Observable Values                 |
+===============================+===================================+=====================================+
| API Calls                     |  | create (CAR)                   | | Sysmon ID 1 (Process Creation)    |
|                               |                                   | | Sysmon ID 5 (Process termination) |
+-------------------------------+-----------------------------------+-------------------------------------+

.. rubric:: References

.. [#f1] https://learn.microsoft.com/en-us/dotnet/visual-basic/programming-guide/com-interop/walkthrough-calling-windows-apis
.. [#f2] https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-api-list
.. [#f3] https://posts.specterops.io/uncovering-window-security-events-ab72e1ec745c
.. [#f4] https://docs.google.com/spreadsheets/d/1d7hPRktxzYWmYtfLFaU_vMBKX2z98bci0fssTYyofdo/edit#gid=0