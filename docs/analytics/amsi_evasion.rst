:orphan:

------------
AMSI Evasion
------------

- https://github.com/SigmaHQ/sigma/blob/7f3eff58e17c1edec877cf45972726588d009940/rules/windows/registry/registry_delete/registry_delete_removal_amsi_registry_key.yml

.. code-block:: yaml

  title: Removal Of AMSI Provider Registry Keys
  id: 41d1058a-aea7-4952-9293-29eaaf516465
  status: test
  description: Detects the deletion of AMSI provider registry key entries in HKLM\Software\Microsoft\AMSI. This technique could be used by an attacker in order to disable AMSI inspection.
  references:
      - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
      - https://seclists.org/fulldisclosure/2020/Mar/45
  author: frack113
  date: 2021/06/07
  modified: 2023/02/08
  tags:
      - attack.defense_evasion
      - attack.t1562.001
  logsource:
      product: windows
      category: registry_delete
  detection:
      selection:
          EventType: DeleteKey
          TargetObject|endswith:
              - '{2781761E-28E0-4109-99FE-B9D127C57AFE}' # IOfficeAntiVirus
              - '{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}' # ProtectionManagement.dll
      condition: selection
  falsepositives:
      - Unlikely
  level: high

Original Analytic Scoring
^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
    :widths: 20 20 30 20
    :header-rows: 1

    * -
      - Application (A)
      - User-mode (U)
      - Kernel-mode (K)
    * - Core to (Sub-) Technique (5)
      -
      -
      -
    * - Core to Part of (Sub-) Technique (4)
      -
      -
      -
    * - Core to Pre-Existing Tool (3)
      -
      -
      -
    * - Core to Adversary-brought Tool (2)
      -
      -
      -
    * - Ephemeral (1)
      -
      -
      - |  EventType: DeleteKey
        |  TargetObject|endswith:
        |    - '{2781761E-28E0-4109-99FE-B9D127C57AFE}'
        |    - '{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}'


Improved Analytic Scoring
^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
    :widths: 15 30 60
    :header-rows: 1

    * - Level
      - Level Name
      - Observables
    * - 7
      - Kernel
      - | TargetObject|contains:
        | - 'Computer\\HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\AMSI\\Providers\\'
    * - 6
      - System Calls
      -
    * - 5
      - OS API
      -
    * - 4
      - Application API
      -
    * - 3
      - Tools Outside Adversary Control
      -
    * - 2
      - Tools Within Adversary Control
      -
    * - 1
      - Operational/Environmental Variables
      -

Research Notes and Caveats
^^^^^^^^^^^^^^^^^^^^^^^^^^
The original analytic relies on the adversary removing the AMSI provider from the
registry. There is a known technique to evade this analytic where an new (Fake) AMSI is
registered in the directory. This moves to detect any change in the directory. This
directory is “special” due to the way the OS uses it in the queuing of AMSI tasking
[#f1]_ . With these modification the adversary cannot add, remove, or modify any values
in this directory, detecting the activity.

.. rubric:: References

.. [#f1] https://learn.microsoft.com/en-us/windows/win32/amsi/dev-audience#register-your-provider-dll-with-amsi
