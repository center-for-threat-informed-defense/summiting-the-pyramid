:orphan:

----------
BloodHound
----------

https://github.com/SigmaHQ/sigma/blob/27aac9763988ade9eca6ee513919691fae0e28e3/rules/windows/file/file_event/file_event_win_bloodhound_collection.yml

.. list-table::
    :widths: 30 70

    * - Original Analytic
      - | selection_1:
        | TargetFilename|endswith:
        |   - '_BloodHound.zip'
        |   - '_computers.json'
        |   - '_containers.json'
        |   - '_domains.json'
        |   - '_gpos.json'
        |   - '_groups.json'
        |   - '_ous.json'
        |   - '_users.json'
        | selection_2:
        | TargetFilename|contains|all:
        |   - 'BloodHound'
        |   - '.zip'
    * - Improved Analytic
      - | | rex field=target_file_name ".*\\\\(?<bloodhound_format>\d{14}_.*\.zip)"?
        | | where isnotnull(bloodhound_format)


Original Analytic Scoring
^^^^^^^^^^^^^^^^^^^^^^^^^
.. list-table::
    :widths: 15 30 60
    :header-rows: 1

    * - Level
      - Level Name
      - Observables
    * - 7
      - Kernel
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
      - | selection_1:
        | TargetFilename|endswith:
        |   - '_BloodHound.zip'
        |   - '_computers.json'
        |   - '_containers.json'
        |   - '_domains.json'
        |   - '_gpos.json'
        |   - '_groups.json'
        |   - '_ous.json'
        |   - '_users.json'
        | selection_2:
        | TargetFilename|contains|all:
        |   - 'BloodHound'
        |   - '.zip'

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
      - | | rex field=target_file_name ".*\\\\(?<bloodhound_format>\d{14}_.*\.zip)"?
        | | where isnotnull(bloodhound_format)
    * - 1
      - Operational/Environmental Variables
      -

Research Notes and Caveats
^^^^^^^^^^^^^^^^^^^^^^^^^^

The original analytic detects specific file names associated with the Active Directory reconaissance tool, BloodHound [#f1]_. 
Several of these file names can be easily changed by an adversary when executing the tool. An alternative detection method might look at the length of 
BloodHound's output zip file, which during testing was always 14 characters long. This characteristic is more challenging for an adversary to evade,
since it would require a recompilation of the tool. This improved analytic moves up a level from Operational/Environmental Variables to Tools Within Adversary Control.

.. rubric:: References
.. [#f1] https://attack.mitre.org/software/S0521/
