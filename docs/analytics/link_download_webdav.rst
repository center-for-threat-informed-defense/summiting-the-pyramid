----------------------------------------------------------
Link (LNK) File Download Containing a WebDAV UNC Hyperlink
----------------------------------------------------------

Original Analytic
^^^^^^^^^^^^^^^^^

.. code-block:: 


  alert http any any - any any
  (
  msg: "POLICY [ANY.RUN] A suspicious Lnk file leading to a WebDAV resource was downloaded";
  flow: established, to_client; 
  http.stat_code;
  content:"200";
  
  file_data;
  content: "|400 0000 01140200 00000000 0000000 00000046|";depth: 28; 
  pcre: "/\x5c\x00\x5c(?:\x00 [a-z0-9\.\-\_])+\x00@/R";
  classtype: policy-violation;
  metadata: tag webdav, created_at 2024_03_20; 
  sid: 8001397; rev: 1;
  )

Analyic Source: `ANY.RUN <https://any.run/cybersecurity-blog/wp-content/uploads/2024/04/9-1.png>`_

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
      - | Payload|beginswith: “4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46” and
        | Regex pattern: “\x5C\x00\x5C(?:\x00[a-z0-9\.\-\_])+\x))@”
      -
    * - Core to Pre-Existing Tool or Inside Boundary (3)
      -
      -
    * - Core to Adversary-Brought Tool or Outside Boundary (2)
      -
      - 
    * - Ephemeral (1)
      - 
      - 

The Suricata rule looks for the 20-byte sequence ``4C 00 00 00 01 14 02 00 00 00
00 00 C0 00 00 00 00 00 00 46`` at the start of the file, and a regular
expression (regex) pattern to match double-backslash ``\\`` followed by an
arbitrary-length series of lowercase letters, digits, periods, dashes, and
underscore characters followed by the ``@`` symbol. According to Microsoft
documentation, the first 4 bytes of an LNK file must equal the hexadecimal value
``0x0000004C``, and the next 16 bytes must equal the Shell Link Class ID
``00021401-0000-0000-C000-000000000046``. [#f1]_  Therefore, the 20-byte sequence in
this Suricata rule is robust enough to specifically identify LNK files, and this
observable would have an analytic robustness score of :ref:`Some
Implementations`. Furthermore, the regex pattern for the WebDAV UNC path is
general enough to allow either an IP address or a host/domain name followed by
the ``@`` symbol. The analytic robustness of the regex pattern is also
:ref:`Some Implementations`. The event robustness is :ref:`Payload`, because it
relies on visibility of the HTTP body section, and the overall robustness score
for this rule is **4P**.

.. rubric:: References

.. [#f1] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943