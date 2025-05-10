.. _Payload:

----------------------------
Column P: Payload Visibility
----------------------------

**Description**: Observables are associated with the relevant network protocol
payload, and sensor visibility into the payload is necessary for detection.

The Payload Visibility event robustness category groups observables that are
transmitted within the network protocol payload. For some network protocols,
sensor visibility into the data payload may be obscured via encryption or
obfuscation applied by the adversary or via encryption applied by the intrinsic
behavior of the operating system, service, or application. Observables
associated with network protocol payload or relying on full, plain-text
visibility into the payload are less robust.

Observables
^^^^^^^^^^^
+-------------------------------+-----------------------------------------------------------------------------------------+
| Category                      | Observable Fields                                                                       |
+===============================+=========================================================================================+
| Network Traffic Content       | Examples include (but are not limited to):                                              |
|                               |                                                                                         |
|                               | * Zeek Event: dce_rpc_request_stub [#f1]_                                               |
|                               | * Zeek Event: http_entity_data [#f2]_                                                   |
|                               | * Suricata rules allow access to the protocol payload. [#f3]_                           |
+-------------------------------+-----------------------------------------------------------------------------------------+

.. rubric:: References

.. [#f1] https://docs.zeek.org/en/current/script-reference/proto-analyzers.html#id-dce_rpc_request_stub
.. [#f2] https://docs.zeek.org/en/current/script-reference/proto-analyzers.html#id-http_entity_data
.. [#f3] https://docs.suricata.io/en/latest/rules/index.html#suricata-rules
