Post-Exploitation Reconnaissance
=================================

Description of Use Case
------------------------
This use case was completely dominated by endpoint telemetry. The results show that detecting an adversary exploring a compromised host is almost exclusively a function of monitoring process execution and command-line arguments. Network and cloud logs were largely irrelevant, as the vast majority of this activity is local to the machine.


Techniques Evaluated
---------------------
* T1082 System Information Discovery
* T1016 System Network Configuration Discovery
* T1018 Remote System Discovery
* T1087 Account Discovery
* T1083 File and Directory Discovery
* T1049 System Network Connections Discovery
* T1033 System Owner/User Discovery
* T1124 System Time Discovery
* T1518 Software Discovery
* T1046 Network Service Scanning
* T1057 Process Discovery
* T1059.001 Command & Scripting Interpreter: PowerShell

Top Scoring Log Sources
-------------------------
.. table::

   +------------------------------------------------------+-------+
   | Log Source                                           | Score |
   +======================================================+=======+
   | EDR: Endpoint Activity                               | 26.1  |
   +------------------------------------------------------+-------+
   | EDR: API Calls                                       | 25.5  |
   +------------------------------------------------------+-------+
   | Other Platform: Microsoft-Windows-Kernel-Process     | 25.3  |
   +------------------------------------------------------+-------+
   | EDR/Sysmon: WMI Events                               | 25.0  |
   +------------------------------------------------------+-------+
   | Sysmon: EID 1: Process Create                        | 24.9  |
   +------------------------------------------------------+-------+
   | Windows PowerShell: EID 4104: Script Block Logging   | 24.5  |
   +------------------------------------------------------+-------+
   | Windows Event Logs: Event ID 400                     | 24.5  |
   +------------------------------------------------------+-------+
   | Windows Event Logs: Event ID 403                     | 24.5  |
   +------------------------------------------------------+-------+
   | Windows Event Logs: Event ID 4103: Module Logging    | 24.5  |
   +------------------------------------------------------+-------+
   | Sysmon: EID 10                                       | 24.4  |
   +------------------------------------------------------+-------+


Key Trends & Generalizations
------------------------------
* **Command-Line Auditing is Non-Negotiable**: This cannot be overstated. If you are not logging process command-line arguments, you have zero effective visibility into post-exploitation reconnaissance activity.

* **"Living Off the Land" is the Default Tactic**: The top log sources are all designed to detect the malicious use of legitimate, built-in system utilities (net.exe, ipconfig, whoami, nltest, etc.). This confirms that adversaries will almost always use what's already on the system before bringing in their own tools.

* **Recon Detection is an Endpoint Game**: The entire story of reconnaissance is told on the compromised endpoint. Your detection strategy, budget, and analyst focus for this phase of an attack should be overwhelmingly centered on host-based telemetry.


Evaluation of Log Source Types
-------------------------------
Process creation logs with full command-line auditing were the massive margin, the most important log type. Scripting logs (PowerShell) were a strong second. API call monitoring was a more advanced but highly valuable third.

**Technology Comparison: EDR ≈ Sysmon >> Native Windows Logs >> Network/Cloud**


Scoring Data
-------------
The raw TC scores broken down by metric can be found here: :download:`Post-Exploitation Reconnaissance<FinalConfidenceScores_Post-Exploit Recon.csv>`
