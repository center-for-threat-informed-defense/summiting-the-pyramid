Execution via Scripting Languages
===================================

Description of Use Case
------------------------
This use case is defined by a single, critical requirement: visibility into the commands and content being fed to script interpreters. The scoring results created a very clear hierarchy. At the top are sources that can capture the full content of the script itself. In the second tier are sources that reliably capture the process creation and full command-line arguments of the interpreters. All other log types proved to be largely irrelevant. 


Techniques Evaluated
---------------------
* T1059 Command & Scripting Interpreter
* T1218.011 Signed Binary Proxy Execution: Rundll32
* T1106 Native API
* T1204 User Execution
* T1047 Windows Management Instrumentation
* T1216 System Script Proxy Execution



Top Scoring Log Sources
-------------------------
.. table::

   +------------------------------------------------------+-------+
   | Log Source                                           | Score |
   +======================================================+=======+
   | Windows PowerShell: EID 4104: Script Block Logging   | 27.2  |
   +------------------------------------------------------+-------+
   | EDR: Suspicious Child Process                        | 27.2  |
   +------------------------------------------------------+-------+
   | EDR: Telemetry (API Calls)                           | 25.8  |
   +------------------------------------------------------+-------+
   | Sysmon: EID 8: CreateRemoteThread                    | 25.8  |
   +------------------------------------------------------+-------+
   | Windows PowerShell: EID 4103: Module Logging         | 25.5  |
   +------------------------------------------------------+-------+
   | Sysmon: EID 1: Process Create                        | 24.7  |
   +------------------------------------------------------+-------+
   | EDR: WMI Events                                      | 24.4  |
   +------------------------------------------------------+-------+
   | Sysmon: EID 19/20/21: WMI Events                     | 24.4  |
   +------------------------------------------------------+-------+
   | Autoruns Data                                        | 23.5  |
   +------------------------------------------------------+-------+
   | Windows Security: EID 4688: Process Creation         | 23.1  |
   +------------------------------------------------------+-------+


Key Trends & Generalizations
------------------------------
* **Content is a Quantum Leap Beyond Command Line**: The superior score of PowerShell Script Block Logging proves a critical point: seeing the full script is an order of magnitude more valuable than seeing the command that launched it. It defeats simple obfuscation and reveals the adversary's full intent. 

* **The Interpreter is the Perfect Choke Point**: Adversaries must use an interpreter to execute their scripts. This makes monitoring the creation and arguments of a small, known list of processes (powershell.exe, cscript.exe, wscript.exe, mshta.exe, python.exe, bash, zsh, etc.) an incredibly high-yield and efficient detection strategy. 

* **Fileless Execution is Mainstream**: The high value of API call monitoring and Script Block Logging highlights that modern attacks are designed to execute entirely in memory. A detection strategy that relies only on seeing files written to disk will fail. You must have visibility into processes, command lines, and script content itself. 


Evaluation of Log Source Types
-------------------------------
There was a very distinct ranking:

* Script Content Logs (PowerShell Script Block): Tier 1, in a class of its own. 
* Process Creation w/ Command-Line Auditing (Sysmon, EDR, EID 4688, ESF, Auditd): Tier 2, the essential baseline for detection. 
* API Call / Module Load Logs (EDR, Sysmon EID 7): Tier 3, for detecting more advanced fileless tradecraft. 
* All other categories, especially Network Logs, were effectively irrelevant as the execution activity is entirely local to the host.

**Technology Comparison: Specialized OS Logging >> EDR/Sysmon >> Generic OS Logs**


Scoring Data
-------------
The raw TC scores broken down by metric can be found here: :download:`Execution via Scripting Languages <FinalConfidenceScores_Execution via Script.csv>`
