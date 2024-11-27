.. _Header:

---------------------------
Column P: Header Visibility
---------------------------

**Description**: Observables associated with the relevant network protocol header.

The Header Visibility event robustness category groups observables that are transmitted as part of the network protocol header. For most network protocols, even encryption protocols like Internet Protocol Security (IPSEC) and Transport Layer Security (TLS), the header section of the protocol must be transmitted in plain text, while only the data payload would be encrypted or obfuscated. For example, with IPSEC (OSI Layer 3), the IP header would be visible in plain text, but the IP payload would be encrypted. With TLS (OSI Layer 4), the TCP header would be visible in plain text, but the TCP payload would be encrypted. With RPC (OSI Layer 7), the RPC header would be visible in plain text, but the RPC payload could be encrypted. Observables associated with the network protocol header, and therefore not affected by payload encryption or obfuscation, are more robust.

Observables
^^^^^^^^^^^
+-------------------------------+-----------------------------------------------------------------------------------------+
| Category                      | Observable Fields                                                                       |
+===============================+=========================================================================================+
| Named Pipe Access             | | Zeek Log: dce_rpc.log [#f1]_                                                          |
|                               | | - named_pipe                                                                          |
|                               | | Zeek Log: smb_files.log [#f1]_                                                        |
|                               | | - path: \*\IPC$                                                                       |
+-------------------------------+-----------------------------------------------------------------------------------------+
| Network Share Access          | | Zeek Log: smb_files.log                                                               |
|                               | | - path                                                                                |
|                               | | Zeek Log: smb_mapping.log [#f1]_                                                      |
|                               | | - path                                                                                |
+-------------------------------+-----------------------------------------------------------------------------------------+
| Network Traffic Connection    | | Zeek Log: conn.log [#f1]_                                                             |
|                               | | - id$orig_h                                                                           |
|                               | | - id$orig_p                                                                           |
|                               | | - id$resp_h                                                                           |
|                               | | - id$resp_p                                                                           |
|                               | | - proto                                                                               |
|                               | | - service                                                                             |
|                               | | - duration                                                                            |
+-------------------------------+-----------------------------------------------------------------------------------------+
| Network Traffic Flow          | | Zeek Log: conn.log [#f1]_                                                             |
|                               | | - id$orig_h                                                                           |
|                               | | - id$orig_p                                                                           |
|                               | | - id$resp_h                                                                           |
|                               | | - id$resp_p                                                                           |
|                               | | - proto                                                                               |
|                               | | - service                                                                             |
|                               | | - duration                                                                            |
+-------------------------------+-----------------------------------------------------------------------------------------+
| Scheduled Job Creation        | | Zeek Log: dce_rpc.log                                                                 |
| (Remote)                      | | - endpoint: ITaskScheduler                                                            |
|                               | | - operation: SchRpcRegisterTask, SchRpcEnableTask, SchRpcRun                          |
+-------------------------------+-----------------------------------------------------------------------------------------+
| Service Creation (Remote)     | | Zeek Log: dce_rpc.log                                                                 |
|                               | | - endpoint: ITaskScheduler                                                            |
|                               | | - operation: CreateWowService, CreateService, StartService                            |
+-------------------------------+-----------------------------------------------------------------------------------------+
| WMI                           | | Zeek Log: dce_rpc.log                                                                 |
|                               | | - endpoint: IWbemServices                                                             |
|                               | | - operation: ExecMethod, ExecMethodAsync                                              |
+-------------------------------+-----------------------------------------------------------------------------------------+
| Windows Registry Key Access   | | Zeek Log: dce_rpc.log                                                                 |
| (Remote)                      | | - endpoint: winreg                                                                    |
|                               | | - operation: BaseRegOpenKey                                                           |
+-------------------------------+-----------------------------------------------------------------------------------------+
| Windows Registry Key Creation | | Zeek Log: dce_rpc.log                                                                 |
| (Remote)                      | | - endpoint: winreg                                                                    |
|                               | | - operation: BaseRegCreateKey                                                         |
+-------------------------------+-----------------------------------------------------------------------------------------+
| Windows Registry Key Deletion | | Zeek Log: dce_rpc.log                                                                 |
| (Remote)                      | | - endpoint: winreg                                                                    |
|                               | | - operation: BaseRegDeleteKey, BaseRegDeleteValue                                     |
+-------------------------------+-----------------------------------------------------------------------------------------+
| Windows Registry Key          | | Zeek Log: dce_rpc.log                                                                 |
| Modification (Remote)         | | - endpoint: winreg                                                                    |
|                               | | - operation: BaseRegSetValue                                                          |
+-------------------------------+-----------------------------------------------------------------------------------------+

.. rubric:: References

.. [#f1] https://docs.zeek.org/en/current/script-reference/log-files.html#network-protocols