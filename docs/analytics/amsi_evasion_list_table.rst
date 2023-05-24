------------
AMSI Evasion
------------

- https://github.com/SigmaHQ/sigma/blob/7f3eff58e17c1edec877cf45972726588d009940/rules/windows/registry/registry_delete/registry_delete_removal_amsi_registry_key.yml

.. list-table::
    :widths: 30 70

    * - Original Analytic
      - | EventType: DeleteKey
        | TargetObject|endswith:
        |    - '{2781761E-28E0-4109-99FE-B9D127C57AFE}' # IOfficeAntiVirus
        |    - '{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}' # ProtectionManagement.dll
    * - Improved Analytic
      - | TargetObject|contains: 
        |    - 'Computer\\HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\AMSI\\Providers\\' 

Original Analytic Scoring
^^^^^^^^^^^^^^^^^^^^^^^^^
.. list-table::
    :widths: 15 30 60
    :header-rows: 1

    * - Level
      - Level Name
      - Observables
    * - 7
      - Kernel/Interfaces
      - 
    * - 6
      - System Calls
      - 
    * - 5
      - OS API
      - 
    * - 4
      - Library API
      - 
    * - 3
      - Tools Outside Adversary Control
      - 
    * - 2
      - Tools Within Adversary Control
      - 
    * - 1
      - Operational/Environmental Variables
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
      - Kernel/Interfaces
      - | TargetObject|contains:
        | - 'Computer\\HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\AMSI\\Providers\\'
    * - 6
      - System Calls
      - 
    * - 5
      - OS API
      - 
    * - 4
      - Library API
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
The original analytic relies on the adversary removing the AMSI provider from the registry. There is a known 
technique to evade this analytic where an new (Fake) AMSI is registered in the directory. This moves to detect 
any change in the directory. This directory is “special” due to the way the OS uses it in the queuing of AMSI 
tasking [#f1]_ . With these modification the adversary cannot add, remove, or modify any values in this directory, 
detecting the activity.

.. rubric:: References

.. [#f1] https://learn.microsoft.com/en-us/windows/win32/amsi/dev-audience#register-your-provider-dll-with-amsi
