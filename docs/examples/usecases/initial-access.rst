Initial Access via Spearphishing
=================================

Description of Use Case
------------------------
This specific and linear attack chain—from attachment to user click, command shell, and tool download—places an enormous emphasis on endpoint process execution monitoring. While perimeter controls like email gateways are vital for prevention, the moment the user executes the file, the entire detection game shifts to the endpoint. The scoring overwhelmingly favors technologies that can spot the anomalous process lineage that is the hallmark of this attack.


Techniques Evaluated
---------------------
* T1024 User Execution: Malicious File
* T1556.001 Phishing: Spearphishing Attachment
* T1059.003 Command & Scripting Interpreter: Windows Command Shell
* T1218.011 Signed Binary Proxy Execution: Rundll32
* T1036.005 Masquerading: Match Legitimate Name or Location
* T1105 Ingress Tool Transfer


Top Scoring Log Sources
-------------------------
.. table::

   +------------------------------------------------------+-------+
   | Log Source                                           | Score |
   +======================================================+=======+
   | EDR: Suspicious Child Process                        | 27.4  |
   +------------------------------------------------------+-------+
   | EDR: Telemetry                                       | 25.9  |
   +------------------------------------------------------+-------+
   | Secure Email Gateway (SEG) Alerts                    | 25.9  |
   +------------------------------------------------------+-------+
   | EDR: API Calls (Downloads, Process Injection)        | 24.8  |
   +------------------------------------------------------+-------+
   | Sysmon: EID 1: Process Create                        | 24.7  |
   +------------------------------------------------------+-------+
   | Windows Defender: AV Detections                      | 24.4  |
   +------------------------------------------------------+-------+
   | Windows Security: EID 4688: Process Creation         | 23.2  |
   +------------------------------------------------------+-------+
   | Sysmon: Digital Signature Validation Status          | 22.8  |
   +------------------------------------------------------+-------+
   | Zeek/Bro: http.log / files.log                       | 22.8  |
   +------------------------------------------------------+-------+
   | Web Proxy / TLS Inspection Logs                      | 21.5  |
   +------------------------------------------------------+-------+


Key Trends & Generalizations
------------------------------
* **The Initial Execution is the "Golden Signal"**: The entire detection strategy hinges on spotting the moment the user-opened document or program spawns a command interpreter (cmd.exe) or a proxy execution binary (rundll32.exe). This parent-child relationship is the single most reliable and high-confidence indicator of compromise in this entire chain.

* **Defense is a Race Between Prevention and Detection**: The scores show a two-pronged approach. The SEG is trying to prevent the delivery. The moment it fails, the EDR/Sysmon is in a race to detect the execution. A strategy that relies on only one of these will fail.

* **Command-Line Auditing is Everything**: For detecting the abuse of native binaries like cmd.exe and rundll32.exe, the process name itself is useless (it's legitimate). All malicious intent is revealed in the command-line arguments. Therefore, logging process command lines is not optional; it is the central requirement for detecting this entire category of attack.


Evaluation of Log Source Types
-------------------------------
Endpoint Behavioral Alerts (like Suspicious Child Process) proved to be the highest value for detection. This was followed closely by raw Endpoint Process Creation Logs. Prevention-focused Email Security Alerts were also top-tier. Network and file creation logs were important but secondary, providing supporting evidence for the Ingress Tool Transfer phase.

**Technology Comparison: EDR > Sysmon > Native Windows Logs**