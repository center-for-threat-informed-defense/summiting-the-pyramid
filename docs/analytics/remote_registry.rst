--------------------------------------------
Remote Registry Management Using Reg Utility
--------------------------------------------

- https://github.com/SigmaHQ/sigma/blob/f33530e7561d98bc6f898f5a9137c3b2a7159a1b/rules-placeholder/windows/builtin/security/win_security_remote_registry_management_via_reg.yml 

.. code-block:: yaml

    title: Remote Registry Management Using Reg Utility
    id: 68fcba0d-73a5-475e-a915-e8b4c576827e
    status: test
    description: Remote registry management using REG utility from non-admin workstation
    references:
        - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
    author: Teymur Kheirkhabarov, oscd.community
    date: 2019-10-22
    modified: 2023-12-15
    tags:
        - attack.credential-access
        - attack.defense-evasion
        - attack.discovery
        - attack.s0075
        - attack.t1012
        - attack.t1112
        - attack.t1552.002
    logsource:
        product: windows
        service: security
    detection:
        selection:
            EventID: 5145
            RelativeTargetName|contains: '\winreg'
        filter_main:
            IpAddress|expand: '%Admins_Workstations%'
        condition: selection and not filter_main
    falsepositives:
        - Legitimate usage of remote registry management by administrator
    level: medium

Original Host-Based Analytic Scoring
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. list-table::
    :widths: 20 20 20 30
    :header-rows: 1

    * -
      - Application (A)
      - User-Mode (U)
      - Kernel-Mode (K)
    * - Core to (Sub-) Technique (5)
      -
      -
      -
    * - Core to Part of (Sub-) Technique (4)
      -
      -
      - | Event ID: 5145
        | RelativeTargetName|contains: '\\winreg'
    * - Core to Pre-Existing Tool or Inside Boundary (3)
      -
      -
      -
    * - Core to Adversary-Brought Tool or Outside Boundary (2)
      -
      - 
      - 
    * - Ephemeral (1)
      -
      - 
      - | Filter: IpAddress|expand: '%Admins_Workstations%'

Improved Analytic Scoring #1
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. list-table::
    :widths: 20 20 20 30
    :header-rows: 1

    * -
      - Application (A)
      - User-Mode (U)
      - Kernel-Mode (K)
    * - Core to (Sub-) Technique (5)
      -
      -
      -
    * - Core to Part of (Sub-) Technique (4)
      -
      -
      - | Event ID: 5145
        | RelativeTargetName|contains: 'winreg'
    * - Core to Pre-Existing Tool or Inside Boundary (3)
      -
      -
      - | Filter: SubjectUserName|expand: '%Admins_Workstations%'
    * - Core to Adversary-Brought Tool or Outside Boundary (2)
      -
      - 
      - 
    * - Ephemeral (1)
      -
      - 
      - 

This analytic specifically looks at Event ID 5145, which generates every time a network share object is accessed. At a glance, this can look like Sysmon 18, but when access is requested for the network share itself the field appears as ``\``. [#f1]_ Event ID 5145 was given a score of :ref:`Kernel-Mode` due to the level of permission needed at the kernel level to access network share objects. This analytic is looking for any remote access to the registry and is filtering on the remote source, giving it a score of :ref:`Some Implementations`, making the total score for this observable a **4K**. 

The initial score for the filter was a **1K** because it would be easy for an adversary to change or spoof the IP address the filter is targeting. Additionally, IPs can be shared and frequently change from user to user within an internal network, making the filter not precise. When the Boolean logic is used to combine the scores, **we get a total analytic score of 1K**.

However, the score can be improved in two ways. First, the filter target can be improved by using ``SubjectUserName`` instead of ``IpAddress``. By using a username instead of an ephemeral IP address, the filter now targets a field that calls an specific ID set and managed by the enterprise. The filter score increases to a 3K, which then increases the overall analytic score to a **3K** as well.

Additionally, the ``RelativeTargetName`` value can remove the use of “\”. According to Microsoft documentation, if access is requested to the share itself, then the value of RelativeTargetName would equal ``\``, rather than contain a slash pre-pended to the pipe name. To ensure the analytic is working properly, the slash should be removed from the ``RelativeTargetName``.

Original Network Traffic Analytic Scoring
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
        | named_pipe: winreg
        | **Zeek Log: smb_files.log**
        | - path: \*\\IPC$
        | - name: winreg
    * - Core to Pre-Existing Tool or Inside Boundary (3)
      -
      - | Filter: SubjectUserName|expand: '%Admins_Workstations%'
    * - Core to Adversary-Brought Tool or Outside Boundary (2)
      -
      - 
    * - Ephemeral (1)
      - 
      - 

The network analytic shown above is the network equivalent of the host-based analytic, which simply detects remote access to the registry via the Windows Remote Registry Protocol via the named pipe ``winreg``. However, simply detecting the named pipe is very broadly scoped and would not necessarily indicate that a user or adversary is attempting to modify the registry by creating new keys or setting new values. It is possible to create a more detailed detection analytic by leveraging other fields within Zeek’s dce_rpc.log and identifying the specific RPC operations observed within the network traffic.

Improved Analytic Scoring #2
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
        | endpoint: winreg
        | operation:
        | - BaseRegCreateKey
        | - BaseRegSetValue
    * - Core to Pre-Existing Tool or Inside Boundary (3)
      -
      - | Filter: SubjectUserName|expand: '%Admins_Workstations%'
    * - Core to Adversary-Brought Tool or Outside Boundary (2)
      -
      - 
    * - Ephemeral (1)
      - 
      - 

.. rubric:: References

.. [#f1] https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145