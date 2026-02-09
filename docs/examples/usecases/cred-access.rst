Credential Access and Abuse
============================

Description of Use Case
------------------------
This is a use case of two distinct halves: dumping credentials from systems and abusing credentials to authenticate. The scoring reflects this perfectly. For dumping, endpoint memory and API monitoring are supreme. For abuse, detailed authentication logs (both on-prem and cloud) are the most critical. The highest scores went to specialized sensors purpose-built for detecting these specific activities.


Techniques Evaluated
---------------------
* T1078 Valid Accounts
* T1110.003 Password Spraying
* T1003.001 LSASS Memory
* T1558.003 Pass-the-Ticket
* T1550.003 Pass-the-Hash
* T1098 Account Manipulation
* T1555 Credentials from Password Stores
* T1621 Multi-Factor Authentication Request Generation
* T1528 Steal Application Access Token
* T1552.001 Unsecured Credentials: Files


Top Scoring Log Sources
-------------------------
.. table::

   +------------------------------------------------------+-------+
   | Log Source                                           | Score |
   +======================================================+=======+
   | EDR: Credential Dumping / LSASS                      | 26.5  |
   +------------------------------------------------------+-------+
   | Sysmon: EID 10: Process Access (LSASS)               | 26.5  |
   +------------------------------------------------------+-------+
   | Azure AD Identity Protection Alerts                  | 26.4  |
   +------------------------------------------------------+-------+
   | EDR: API Calls                                       | 25.8  |
   +------------------------------------------------------+-------+
   | EDR: Auth w/ NTLM/Pass-the-Hash                      | 25.6  |
   +------------------------------------------------------+-------+


Key Trends & Generalizations
------------------------------
* **Dumping and Abuse Require Different Tools**: A key insight from the scores is that the tools you need to see credentials being stolen (EDR, Sysmon EID 10) are different from the tools you need to see them being used (Azure AD IP, Windows Event 4769/4624). A complete strategy must have best-of-breed telemetry for both halves of the problem.

* **The Cloud is the New Authentication Hub**: The high score of Azure AD Identity Protection highlights a major shift. As organizations move to hybrid identity, the cloud provider's own security tools, which have a global view of sign-in analytics, become more powerful for detecting abuse like password spraying than any single on-premise log source.

* **For Dumping, Memory is Everything**: The near-perfect scores of LSASS access detectors confirm that for T1003 (the most common dumping technique), direct memory monitoring is the only reliable detection strategy. Any security posture that lacks this specific capability is vulnerable to having its credentials silently stolen.


Evaluation of Log Source Types
-------------------------------
The data clearly splits into two top-tier categories: Memory/API Monitoring for the dumping phase and Detailed Authentication Logs for the abuse phase. Generic process logs are a solid secondary source, useful for seeing the tools being run, while generic file logs are a distant third.

**Technology Comparison: Endpoint Security (EDR/Sysmon) & Cloud Identity Protection are co-dominant > Native Windows Authentication Logs**