Observables Quick Search
========================

.. list-table:: Difficulty of Bypassing Analytic Observables
   :widths: 25 75
   :header-rows: 1

   * - Level Name
     - Observables
   * - 5: Core to Sub-Technique or Technique
     - Key: Tasks (T1053)
   * - 4: Core to Some Implementations of (Sub-)Technique
     - AttributeLDAPDisplayName: msDS-KeyCredentialLink (T1556)
   * - 3: Core to Pre-Existing Tools
     - signer (CAR), signature_valid (CAR), mime_type (CAR), link_target (CAR), command line (Sysmon), parent command line (Sysmon), process command line (Windows EID), command_line (CAR), parent_comand_line (CAR), integrity level (Sysmon), mandatory label (Windows EID), token elevation type (Windows EID), original file name (Sysmon), access_level (CAR), integrity_level (CAR), login_type (CAR), login_successful (CAR), auth_service (CAR), decision_reason (CAR), method (CAR)
   * - 2: Core to Adversary-Brought Tools
     - Command line (Sysmon), integrity level (Sysmon), parent command line (Sysmon)
   * - 1: Ephemeral Values
     - Hashes (Sysmon), md5_hash (CAR), sha1_hash (CAR), sha256_hash (CAR), target_address (CAR), dest_ip (CAR), src_ip (CAR), dest_port (CAR), src_port (CAR), image (Sysmon), parent image (Sysmon), current directory (Sysmon), extension (CAR), file_name (CAR), file_path (CAR), image_path (CAR), current_working_directory (CAR), exe (CAR), parent_exe (CAR), app_name (CAR), auth_target (CAR), fqdn (CAR), ad_domain (CAR), target_ad_domain (CAR), process GUID (Sysmon), process ID (Sysmon), parent process GUID (Sysmon), parent process ID (Sysmon), Subject SID (Windows), target SID (Windows EID), new process ID (Windows EID), creator process ID (Windows EID), pid (CAR), ppid (CAR), user (Sysmon), logon GUID (Sysmon), logon ID (Sysmon), subject name (Windows EID), subject domain (Windows EID), subject logon ID (Windows EID), target domain (Windows EID), target logon ID (Windows EID), new process name (Windows EID), creator process name (Windows EID), gid (CAR), group (CAR), owner_uid (CAR), owner (CAR), user (CAR), uid (CAR), guid (CAR), hostname (CAR), target_guid (CAR), target_uid (CAR), target_user (CAR), target_user_role (CAR), target_user_type (CAR), target_name (CAR), target_pid (CAR), login_id (CAR), user_agent (CAR), user_role (CAR), contents (CAR), creation_time (CAR), mode (CAR), previous_creation_time (CAR), env_vars (CAR), data (CAR), new_content (CAR), value (CAR), response_time


.. list-table:: Collection Sources
   :widths: 30 70
   :header-rows: 1

   * - Column Name
     - Collection Observables
   * - Library (L)
     - Event ID 4698, Event ID 4699, Event ID 4700, Event ID 4701, Event ID 4702
   * - User-Mode (U)
     - Sysmon ID 1, Sysmon ID 5, Sysmon ID 2, Sysmon ID 10, Sysmon ID 11, Sysmon ID 15, Sysmon ID 23, Sysmon ID 6, Sysmon ID 13, Sysmon ID 14
   * - Kernel-Mode (K)
     - Event ID 4688, Event ID 4689, Sysmon ID 8, Event ID 4663, Event ID 4656, Sysmon ID 12, Event ID 4660, Event ID 4657