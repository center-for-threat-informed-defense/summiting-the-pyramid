---------------------------------------------------
Executable (EXE) File Download from a WebDAV Server
---------------------------------------------------

- https://github.com/SigmaHQ/sigma/blob/6048be5a7a3bf3b923fd4ee8236fed59ef7ff6a1/rules/network/zeek/zeek_http_executable_download_from_webdav.yml 

.. code-block:: yaml

  title: Executable from Webdav
  id: aac2fd97-bcba-491b-ad66-a6edf89c71bf
  status: test
  description: 'Detects executable access via webdav6. Can be seen in APT 29 such as from the emulated APT 29 hackathon https://github.com/OTRF/detection-hackathon-apt29/'
  references:
      - http://carnal0wnage.attackresearch.com/2012/06/webdav-server-to-download-custom.html
      - https://github.com/OTRF/detection-hackathon-apt29
  author: 'SOC Prime, Adam Swan'
  date: 2020-05-01
  modified: 2021-11-27
  tags:
      - attack.command-and-control
      - attack.t1105
  logsource:
      product: zeek
      service: http
  detection:
      selection_webdav:
          - c-useragent|contains: 'WebDAV'
          - c-uri|contains: 'webdav'
      selection_executable:
          - resp_mime_types|contains: 'dosexec'
          - c-uri|endswith: '.exe'
      condition: selection_webdav and selection_executable
  falsepositives:
      - Unknown
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
      -
    * - Core to Pre-Existing Tool or Inside Boundary (3)
      -
      -
    * - Core to Adversary-Brought Tool or Outside Boundary (2)
      -
      - | c-uri|contains: 'webdav'
        | c-uri|endswith: '.exe'
    * - Ephemeral (1)
      - | resp_mime_types|contains: 'dosexec'
      - | c-useragent|contains: 'WebDAV'

This analytic detects executable access via the WebDAV6 tool, as identified through two selections. The analytic would trigger if the UserAgent and the URI contain ``webdav``, both of which are contained within the header. The analytic would also trigger if the responder’s list of mime types contains ``dosexec``, which is contained in the payload, and the URI ends with ``.exe``, which is visible in the header.

The first selection scores as **1H** in its entirety. On its own, ``c-uri|contains: ‘webdav’`` scores individually as a **2H**, as WebDAV is an adversary-brought tool whose URI format does not change and will always contain ``webdav``. However, it is ANDed with ``c-useragent|contains: ‘WebDAV’``, which scores as a **1H**, due to the UserAgent being ephemeral and easily changed. Since the scores are ANDed, together they come out as a **1H**.

The second selection scores as a **1P**, as while ``c-uri|endswith: ‘.exe’`` would individually score as a **2H**, due to the unchangeable nature of WebDAV’s URIs, it is ANDed with ``resp_mime_types|contains: ‘dosexec’``, which scores as a **1P**. This is a Zeek field that looks at the HTTP log to see if the keyword ``dosexec`` is present in the ordered vector of mime types from the responder. This keyword is ephemeral and requires visibility into the payload, making it a **1P** in total.

As the final score of the analytic is the greater of both selections, due to them not being dependent on each other through OR Boolean logic, we get a total analytic score of **1H**.

