.. _AD Find:

-----------------
ADFind
-----------------

Original Analytic
^^^^^^^^^^^^^^^^^

.. code-block:: yaml

  title: Suspicious AdFind Execution
  id: 75df3b17-8bcc-4565-b89b-c9898acef911
  status: experimental
  description: Detects the execution of a AdFind for Active Directory enumeration
  references:
      - https://social.technet.microsoft.com/wiki/contents/articles/7535.adfind-command-examples.aspx
      - https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/master/fin6/Emulation_Plan/Phase1.md
      - https://thedfirreport.com/2020/05/08/adfind-recon/
  author: FPT.EagleEye Team, omkar72, oscd.community
  date: 2020/09/26
  modified: 2021/05/12
  tags:
      - attack.discovery
      - attack.t1018
      - attack.t1087.002
      - attack.t1482
      - attack.t1069.002
  logsource:
      product: windows
      category: process_creation
  detection:
      selection:
          CommandLine|contains:
              - 'objectcategory'
              - 'trustdmp'
              - 'dcmodes'
              - 'dclist'
              - 'computers_pwdnotreqd'
          Image|endswith: '\adfind.exe'
      condition: selection
  falsepositives:
      - Administrative activity
  level: medium

Analytic Source: `SigmaHQ <https://github.com/SigmaHQ/sigma/blob/30bee7204cc1b98a47635ed8e52f44fdf776c602/rules/windows/process_creation/win_susp_adfind.yml>`_

Original Analytic Scoring
^^^^^^^^^^^^^^^^^^^^^^^^^

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
      -
    * - Core to Pre-Existing Tool or Inside Boundary (3)
      -
      -
      -
    * - Core to Adversary-Brought Tool or Outside Boundary (2)
      -
      - 
      - | EventID: 1
        | CommandLine|contains:
        |   - 'objectcategory'
        |   - 'trustdmp'
        |   - 'dcmodes'
        |   - 'dclist'
        |   - 'computers_pwdnotreqd'
    * - Ephemeral (1)
      -
      - 
      - Image|endswith: '\\adfind.exe'

Improved Analytic Scoring
^^^^^^^^^^^^^^^^^^^^^^^^^

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
      -
    * - Core to Pre-Existing Tool or Inside Boundary (3)
      -
      -
      -
    * - Core to Adversary-Brought Tool or Outside Boundary (2)
      -
      - 
      - | EventID: 1
        | CommandLine|contains:
        |   - 'objectcategory'
        |   - 'trustdmp'
        |   - 'dcmodes'
        |   - 'dclist'
        |   - 'computers_pwdnotreqd'
        | OriginalFileName|endswith: '\\adfind.exe'
    * - Ephemeral (1)
      -
      -
      -

This analytic looks for specific command-line arguments of the ADFind tool,
identified when ``Image`` ends with ``adfind.exe``. The logsource for this
analytic is ``process_creation``, so it could potentially fire for Windows Event
ID 4688 or Sysmon Event ID 1. This analytic references the ``Image`` field,
which does not exist in Event ID 4688 but does exist in Sysmon Event ID 1.
[#f1]_ Event ID 4688 has the field NewProcessName, though it could be mapped to
another field name in your SIEM of choice. We proceed with the interpretation
that 4688 events will not be returned, and therefore score this using Event ID
1.

Sysmon Event ID 1 is generated when Win32 API functions are called to create a
new process. [#f2]_  However, instead of operating from a userland artifact, it
awaits a kernel callback to notify it via the
``PsSetCreateProcessNotifyRoutineEx`` function that a new process has been
created. The aforementioned routine is normally triggered by the driver any time
a new process is registered with the kernel, at which point it notifies all
drivers in its callback array of the new process registration. Although it is
possible for the notification routine to be avoided, doing so generally requires
modifying either Sysmon (to suppress the driver callback) or the driver itself
(to avoid notifications of process registration ever being sent out), both of
which are quite impractical. Therefore, it is a kernel-mode log source and we
can place the observables in the :ref:`Kernel-Mode`.

``Image|endswith: '\adfind.exe'`` is placed at the :ref:`Ephemeral Values`. An
adversary can easily obfuscate or change the Image value by renaming the file.
The command-line arguments are placed at :ref:`Adversary Brought Tool`, since
the command-line arguments are specific to the ADFind tool and require modifying
source code to change. Since the ``CommandLine`` and ``Image`` observables in
the analytic are ANDed together, according to our Boolean logic, the entire
analytic scores as a **1K**.

The robustness of this analytic can be increased by leveraging the
``OriginalFileName`` field in Sysmon Event ID 1 instead of ``Image``. It is
trivial for an adversary to change the ``Image`` name ending with ``adfind.exe``
to avoid detection. It is more challenging for an adversary to change the
``OriginalFileName``, since it is derived from the PE header. Changing the PE
header requires either modifying values at the executable's compile time or
modifying raw bytes with a hex editor, both of which are more complex for an
adversary than renaming a file on a compromised system.

By instead detecting ``OriginalFileName|endswith: '\adfind.exe'``, this analytic
moves up a level to **2K**.

Another approach to improve the robustness of this analytic is to drop the
condition of the ``Image`` or ``OriginalFileName`` completely since the
command-line arguments specified in the first clause are likely unique to the
ADFind tool. Adding that second clause adds a way for an adversary to evade the
analytic without decreasing accuracy.


.. rubric:: References

.. [#f1] https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001
.. [#f2] https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
