Analytics Repository
====================

This repository contains analytics which our team has gathered from different sources for improvement based on our methodology. If there's any comments, questions, or an analytic you would like us to test, please feel free to reach out on our GitHub page!

.. list-table:: Analytics Repository
    :widths: 40 75 75 50
    :header-rows: 1

    * - Name
      - Original Analytic
      - Improved Analytic
      - Notes
    * - `Suspicious DLLHost Activity <https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_dllhost_no_cli_execution.yml#L22>`_
      - command="dllhost.exe" ImageFileName="\\dllhost.exe"
      - ImageFileName="*\\dllhost.exe" (parent_file_name="scrons.exe" OR lsass OR command="*dllhost.exe")
      - This activity has multiple IOCs that you can look for to increase your likelyhood of detection.
    * - `Bloodhound <https://github.com/splunk/security_content/blob/develop/detections/endpoint/detect_sharphound_file_modifications.yml>`_
      - "(((TargetFilename IN (""*_BloodHound.zip"", ""*_computers.json"", ""*_containers.json"", ""*_domains.json"", ""*_gpos.json"", ""*_groups.json"",?""*_ous.json"", ""*_users.json"")?OR  ((TargetFilename=""*BloodHound*"") AND (TargetFilename=""*.zip*"")))"
      - "| rex field=target_file_name "".*\\\\(?<bloodhound_format>\d{14}_.*\.zip)""? | where isnotnull(bloodhound_format)"
      - Looking for the file format is more robust then just looking for wildcards with file endings.
    * - `Disabled AMSI <https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_delete/registry_delete_removal_amsi_registry_key.yml>`_
      - "    selection: EventType: DeleteKey TargetObject|endswith: - '{2781761E-28E0-4109-99FE-B9D127C57AFE}' - '{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}' "
      - "    selection: TargetObject|contains: - 'Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\AMSI\Providers\' "
      - Rather then just looking at the keys for one EDR solution look at the directory. Also expand the peramitors from just key deletions to any modification. 
    * - `Suspicious ADFind <https://github.com/SigmaHQ/sigma/blob/30bee7204cc1b98a47635ed8e52f44fdf776c602/rules/windows/process_creation/win_susp_adfind.yml>`_
      - "    selection: CommandLine|contains: - 'objectcategory' - 'trustdmp' - 'dcmodes' - 'dclist' - 'computers_pwdnotreqd' Image|endswith: '\adfind.exe'"
      - "    selection: CommandLine|contains: - 'objectcategory' - 'trustdmp' - 'dcmodes' - 'dclist' - 'computers_pwdnotreqd' OriginalFileName: ?adfind.exe?"
      - By switching to the OriginalFileName can not be evaded by simply changing the name of the file. 

