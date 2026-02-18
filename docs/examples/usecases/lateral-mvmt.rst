Lateral Movement
================

Description of Use Case
------------------------
This use case was dominated by sources that provide deep visibility into authentication protocols and remote process creation. The highest scores went to telemetry that could differentiate between a normal user logon and a compromised credential being used for malicious remote execution (e.g., Pass-the-Hash).


Techniques Evaluated
---------------------
* T1570 Lateral Tool Transfer
* T1021.001 Remote Desktop Protocol
* T1021.002 SMB/Windows Admin Shares
* T1021.003 Distributed Component Object Model
* T1021.004 SSH
* T1021.006 Windows Remote Management
* T1550.003 Pass-the-Hash
* T1210 Exploitation of Remote Services
* T1569.002 Service Execution


Top Scoring Log Sources
-------------------------
.. table::

   +------------------------------------------------------+-------+
   | Log Source                                           | Score |
   +======================================================+=======+
   | EDR: Auth w/ NTLM/Pass-the-Hash                      | 26.1  |
   +------------------------------------------------------+-------+
   | EDR: Process Execution                               | 25.9  |
   +------------------------------------------------------+-------+
   | Sysmon: EID 25: Process Tampering                    | 25.4  |
   +------------------------------------------------------+-------+
   | Sysmon: EID 10: Process Access                       | 24.9  |
   +------------------------------------------------------+-------+
   | Sysmon: EID 1: Process Create                        | 24.5  |
   +------------------------------------------------------+-------+
   | Sysmon: EID 17/18: Named Pipe Events                 | 24.2  |
   +------------------------------------------------------+-------+
   | Sysmon: EID 3: Network Connection                    | 23.5  |
   +------------------------------------------------------+-------+
   | Windows Security: EID 4688: Process Creation         | 23.0  |
   +------------------------------------------------------+-------+
   | Windows Security: EID 5985: WinRM Remote Mgmt        | 22.9  |
   +------------------------------------------------------+-------+
   | Windows Security: EID 7045: Service Installation     | 22.9  |
   +------------------------------------------------------+-------+


Key Trends & Generalizations
------------------------------
* **Authentication Details Matter More Than the Event**: Simply knowing a logon occurred (Event 4624) is low-value. Knowing it was an NTLM logon originating from a service account on a workstation it never touches is high-value. The top logs provide this detail.

* **Parent-Child Process Relationships Are Critical**: The ability to see what process spawned the remote connection (e.g., services.exe spawning cmd.exe on a remote host) is one of the strongest indicators of lateral movement. This is a core strength of EDR and Sysmon.

* **Detection is Endpoint-Centric**: You cannot effectively detect lateral movement from the network perspective alone. The critical context (user, process, authentication type) exists on the source and destination endpoints, making endpoint telemetry non-negotiable.


Evaluation of Log Source Types
-------------------------------
Process execution and authentication events were the top two categories. Specifically, logs that could parse the details of an authentication event (like NTLM vs. Kerberos) scored much higher than generic logon events. Network connection logs were a solid #3, useful for seeing the connection but lacking the "why" that process logs provide.

**Technology Comparison: EDR ≈ Sysmon >> Native Windows Logs >> Network Gear**


Scoring Data
-------------
The raw TC scores broken down by metric can be found here: :download:`Lateral Movement<FinalConfidenceScores_Lateral Movement.csv>`
