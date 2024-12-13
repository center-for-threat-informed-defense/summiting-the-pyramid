---------------------------------
Zeek DCE-RPC MITRE BZAR Execution
---------------------------------

- https://github.com/SigmaHQ/sigma/blob/master/rules/network/zeek/zeek_dce_rpc_mitre_bzar_execution.yml 

.. code-block:: yaml

  title: MITRE BZAR Indicators for Execution
    id: b640c0b8-87f8-4daa-aef8-95a24261dd1d
    status: test
    description: 'Windows DCE-RPC functions which indicate an execution techniques on the remote system. All credit for the Zeek mapping of the suspicious endpoint/operation field goes to MITRE'
    references:
        - https://github.com/mitre-attack/bzar#indicators-for-attck-execution
    author: '@neu5ron, SOC Prime'
    date: 2020-03-19
    modified: 2021-11-27
    tags:
        - attack.execution
        - attack.t1047
        - attack.t1053.002
        - attack.t1569.002
    logsource:
        product: zeek
        service: dce_rpc
    detection:
        op1:
            endpoint: 'JobAdd'
            operation: 'atsvc'
        op2:
            endpoint: 'ITaskSchedulerService'
            operation: 'SchRpcEnableTask'
        op3:
            endpoint: 'ITaskSchedulerService'
            operation: 'SchRpcRegisterTask'
        op4:
            endpoint: 'ITaskSchedulerService'
            operation: 'SchRpcRun'
        op5:
            endpoint: 'IWbemServices'
            operation: 'ExecMethod'
        op6:
            endpoint: 'IWbemServices'
            operation: 'ExecMethodAsync'
        op7:
            endpoint: 'svcctl'
            operation: 'CreateServiceA'
        op8:
            endpoint: 'svcctl'
            operation: 'CreateServiceW'
        op9:
            endpoint: 'svcctl'
            operation: 'StartServiceA'
        op10:
            endpoint: 'svcctl'
            operation: 'StartServiceW'
        condition: 1 of op*
    falsepositives:
        - Windows administrator tasks or troubleshooting
        - Windows management scripts or software
    level: medium  

Original Analytic Scoring
^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
    :widths: 20 30 30
    :header-rows: 1

    * -
      - Payload (P)
      - Header (H)
    * - Core to (Sub-) Technique (5)
      -
      - 
    * - Core to Part of (Sub-) Technique (4)
      - 
      - | **Zeek Log: dce_rpc.log**
        | T1053.002
        | endpoint: atsvc
        | operation: NetrJobAdd
        |
        | T1053.005
        | endpoint: ITaskScheduler
        | operation:
        | - SchRpcRegisterTask
        | - SchRpcEnableTask
        | - SchRpcRun 
        | 
        | T1047 
        | endpoint: IWbemServices 
        | operation:
        | - ExecMethod 
        | - ExecMethodAsync
        | 
        | T1569.002
        | endpoint: svcctl 
        | operation:
        | - CreateServiceA
        | - CreateServiceW 
        | - StartServiceA
        | - StartServiceW 
    * - Core to Pre-Existing Tool or Inside Boundary (3)
      -
      -
    * - Core to Adversary-Brought Tool or Outside Boundary (2)
      -
      - 
    * - Ephemeral (1)
      - 
      - 

This Sigma detection analytic is based on `MITRE’s BZAR scripts for Zeek <https://github.com/mitre-attack/bzar>`_. It is an aggregation of remote execution techniques leveraging various Windows system services via the RPC protocol. Using Zeek’s dce_rpc.log, this analytic looks at the endpoint field within the log to identify the Windows At Service Remote Protocol (``atsvc``) , Windows Task Scheduler Service Remote Protocol (``ITaskScheduler``),  Windows Management Instrumentation (WMI) Remote Protocol (``IWbemServices``), [#f1]_  and Windows Service Control Manager Remote Protocol (``svcctl``). [#f2]_  This analytic then looks at the operation field to identify certain operations within each Windows service associated with remote execution.

The Sigma detection analytic could benefit from a couple of improvements:

* For `T1053.002 <https://attack.mitre.org/techniques/T1053/002/>`_, the Sigma analytic contains an error where the values for endpoint and operation are transposed. According to the original detection analytic in MITRE’s BZAR, [#f3]_  the endpoint should be ``atsvc``, and the operation should be ``JobAdd``. Interestingly, digging a little deeper, the full name of the operation should be ``NetrJobAdd``, which is the string value defined in Zeek’s ``DCE_RPC::operations table``. [#f4]_  It appears that both the Sigma analytic and the original BZAR scripts contain errors that should be corrected.
* For `T1569.002 <https://attack.mitre.org/techniques/T1569/002/>`_, the Sigma analytic contains four operations related to creating or starting a service: ``CreateServiceA``, ``CreateServiceW``, ``StartServiceA``, ``StartServiceW``. The original release of MITRE’s BZAR in 2019 contained only these four operations, but it was updated in 2020 to include two more operations: ``CreateServiceWOW64A`` and ``CreateServiceWOW64W``. Digging a little deeper, Microsoft more recently updated the Windows Service Control Manager Remote Protocol and added one more relevant operation: ``CreateWowService``. It appears that both the Sigma analytic and the BZAR scripts should be updated to reflect the current state.

Improved Analytic Scoring
^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
    :widths: 20 30 30
    :header-rows: 1

    * -
      - Payload (P)
      - Header (H)
    * - Core to (Sub-) Technique (5)
      -
      - 
    * - Core to Part of (Sub-) Technique (4)
      - 
      - | **Zeek Log: dce_rpc.log**
        | T1053.002
        | endpoint: atsvc
        | operation: NetrJobAdd
        |
        | T1053.005
        | endpoint: ITaskScheduler
        | operation:
        | - SchRpcRegisterTask
        | - SchRpcEnableTask
        | - SchRpcRun 
        | 
        | T1047 
        | endpoint: IWbemServices 
        | operation:
        | - ExecMethod 
        | - ExecMethodAsync
        | 
        | T1569.002
        | endpoint: svcctl 
        | operation:
        | - CreateWowService*
        | - CreateService*
        | - StartService* 
    * - Core to Pre-Existing Tool or Inside Boundary (3)
      -
      -
    * - Core to Adversary-Brought Tool or Outside Boundary (2)
      -
      - 
    * - Ephemeral (1)
      - 
      - 


.. rubric:: References

.. [#f1] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wmi/c476597d-4c76-47e7-a2a4-a564fe4bf814
.. [#f2] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f
.. [#f3] https://github.com/mitre-attack/bzar?tab=readme-ov-file#45-indicators-for-attck-execution
.. [#f4] https://docs.zeek.org/en/current/scripts/base/protocols/dce-rpc/consts.zeek.html#id-DCE_RPC::operations
