Abuse of Native OS Features
============================

Description of Use Case
------------------------
This use case is the quintessential "Living Off the Land" scenario. The results show a clear and decisive victory for endpoint telemetry that provides deep, contextual information about how legitimate OS tools are being used and configured. The highest-scoring sources are those that can look past the trusted name of a process (e.g., ``rundll32.exe``) and see the suspicious parameters or behaviors associated with it. This is not about finding malware but about finding anomalies in legitimate system activity.

Techniques Evaluated
---------------------
* T1218 Signed Binary Proxy Execution
* T1036.005 Masquerading: Match Legitimate Name or Location
* T1059.001 Command & Scripting Interpreter: PowerShell
* T1569 System Services

Top Scoring Log Sources
-------------------------
.. table::

   +------------------------------------------------------+-------+
   | Log Source                                           | Score |
   +======================================================+=======+
   | EDR: Telemetry                                       | 26.4  |
   +------------------------------------------------------+-------+
   | EDR: Suspicious Child Process                        | 26.4  |
   +------------------------------------------------------+-------+
   | EDR: Suspicious Service Creation                     | 25.5  |
   +------------------------------------------------------+-------+
   | EDR: WMI Events                                      | 25.1  |
   +------------------------------------------------------+-------+
   | Sysmon: EID 19/20/21: WMI Events                     | 25.1  |
   +------------------------------------------------------+-------+
   | Autoruns Data                                        | 25.0  |
   +------------------------------------------------------+-------+
   | Sysmon: EID 1: Process Create                        | 24.7  |
   +------------------------------------------------------+-------+
   | EDR: Registry Modifications                          | 24.5  |
   +------------------------------------------------------+-------+
   | Sysmon: EID 13: Registry Value Set                   | 24.5  |
   +------------------------------------------------------+-------+
   | Windows PowerShell: EID 4104: Script Block Logging   | 24.3  |
   +------------------------------------------------------+-------+

Key Trends & Generalizations
------------------------------
* **Detection is About Anomalous Use, Not Malicious Tools**: You are not looking for a "bad file." You are looking for a good file being used badly. Detection logic must be behavioral, focusing on parent-child relationships, unusual command-line arguments, execution from non-standard directories, and connections to external hosts from internal OS processes.

* **Specialized Visibility is Mandatory**: You cannot effectively detect the abuse of WMI, Scheduled Tasks, or System Services without telemetry sources explicitly designed to monitor them. Generic process logs are not enough; you need the logs that say "a WMI filter-to-consumer binding was created" or "a new system service was installed." Visibility into these features must be intentionally enabled.

* **The Command Line is Ground Truth**: The single most important piece of raw data for this use case is the command-line argument. The commands passed to ``rundll32.exe``, ``mshta.exe``, ``schtasks.exe``, ``powershell.exe``, and ``sc.exe`` are what separate legitimate administrative action from malicious execution. Any detection strategy that does not include full command-line logging is functionally blind to this category.

Evaluation of Log Source Types
-------------------------------
* Process Creation logs (with full command line) are the absolute foundation.
* The true top-tier sources are **Specific Feature Logs** (telemetry explicitly designed to monitor WMI, Scheduled Tasks, and System Services), which provide higher context and lower noise than simply seeing ``wmic.exe`` run.
* Scripting logs (PowerShell) are also critical for this vector.

**Technology Comparison: EDR > Sysmon > Native Windows Logs**