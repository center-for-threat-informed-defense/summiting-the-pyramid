------------------------------------------
File Creation Date Changed to Another Year
------------------------------------------

Original Analytic
^^^^^^^^^^^^^^^^^

.. code-block:: yaml

    title: File Creation Date Changed to Another Year
    id: 558eebe5-f2ba-4104-b339-36f7902bcc1a
    status: test
    description: |
        Attackers may change the file creation time of a backdoor to make it look like it was installed with the operating system.
        Note that many processes legitimately change the creation time of a file; it does not necessarily indicate malicious activity.
    references:
        - https://www.inversecos.com/2022/04/defence-evasion-technique-timestomping.html
    author: frack113, Florian Roth (Nextron Systems)
    date: 2022-08-12
    modified: 2022-10-25
    tags:
        - attack.t1070.006
        - attack.defense-evasion
    logsource:
        category: file_change
        product: windows
    detection:
        selection1:
            PreviousCreationUtcTime|startswith: '2022'
        filter1:
            CreationUtcTime|startswith: '2022'
        selection2:
            PreviousCreationUtcTime|startswith: '202'
        filter2:
            CreationUtcTime|startswith: '202'
        gen_filter_updates:
            - Image:
                - 'C:\Windows\system32\ProvTool.exe'
                - 'C:\Windows\System32\usocoreworker.exe'
                - 'C:\Windows\ImmersiveControlPanel\SystemSettings.exe'
            - TargetFilename|startswith: 'C:\ProgramData\USOPrivate\UpdateStore\'
            - TargetFilename|endswith:
                - '.tmp'
                - '.temp'
        gen_filter_tiworker:
            Image|startswith: 'C:\WINDOWS\'
            Image|endswith: '\TiWorker.exe'
            TargetFilename|endswith: '.cab'
        condition: (( selection1 and not filter1 ) or ( selection2 and not filter2 )) and not 1 of gen_filter*
    falsepositives:
        - Changes made to or by the local NTP service
    level: high

Analytic Source: `SigmaHQ <https://github.com/SigmaHQ/sigma/blob/f33530e7561d98bc6f898f5a9137c3b2a7159a1b/rules/windows/file/file_change/file_change_win_2022_timestomping.yml>`_

Original Analytic Scoring
^^^^^^^^^^^^^^^^^^^^^^^^^
.. list-table::
    :widths: 20 15 15 40
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
      - | Event ID: 4656
        | selection1: PreviousCreationUtcTime|startswith: '2022'
        | filter1: CreationUtcTime|startswith: '2022'
        | selection2: PreviousCreationUtcTime|startswith: '202'
        | filter2: CreationUtcTime|startswith: '202'
    * - Core to Pre-Existing Tool or Inside Boundary (3)
      -
      -
      - | Filter
        | Image:
        | - 'C:\Windows\system32\ProvTool.exe'
        | - 'C:\Windows\ImmersiveControlPanel\SystemSettings.exe'
    * - Core to Adversary-Brought Tool or Outside Boundary (2)
      -
      - 
      - 
    * - Ephemeral (1)
      -
      - 
      - | Filter
        | TargetFilename|startswith: 'C:\ProgramData\USOPrivate\UpdateStore\'
        | TargetFilename|endswith:
        | - '.tmp'
        | - '.temp'
        | gen_filter_tiworker:
        |   Image|startswith: 'C:\\WINDOWS\\'
        |   Image|endswith: '\\TiWorker.exe'
        |   TargetFilename|endswith: '.cab'

This analytic aims to identify changes to a file creation date. We are scoring
this analytic based on what it attempts to do, even though the value should be
updated to reflect the correct year. Since it targets
``PreviousCreationUtcTime`` and ``CreationUtcTime``, which are both accurate
fields, this observable was given a score of :ref:`Some Implementations` because
it is part of the time-stomping sub-technique and will not detect all
implementations. Moving on to the filters, the ``Image`` field, which is often
an ephemeral value, is scored at a :ref:`Pre-Existing Tools` because it is a
part of the windows core processes and is specific and defined file values
within the OS. The next filters that target filenames are :ref:`Ephemeral
Values` because an adversary can change them very easily. The last grouping of
filters, ``gen_filter_tiworker``, is also an ephemeral value because these
values are also easy to change. Without including the filter, the analytic would
have a score of 4K, but once the scores are combined using Boolean logic, the
total score would be a **1K**.