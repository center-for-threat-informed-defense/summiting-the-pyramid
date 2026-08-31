How It Works
==============

Implementation Catalog
-------------------------



Sensor Mappings
----------------



Analytic Ingestion
---------------------
The Ingestion step in the pipeline automates rule processing for all of your detection logic. The script recursively steps through a rule directory and its subdirectories and pulls the values from each rule that the calculator needs to determine a coverage score. 

There is no need to clean up the directory. It steps through level by level and only loads in YAML files. The process then uses a combination of regular expressions and context clues to extract the information. 

Extracted Fields: 

+---------------------------+-----------------------------------------------------------------------+
| Field Extracted           | Description                                                           |
+---------------------------+-----------------------------------------------------------------------+
| rule_title                | The title of the SIGMA rule                                           |
| rule_logsource_product    | The product that the rule was created to defend                       |
| rule_logsource_category   | The type of log that the rule is from                                 |
| rule_tags                 | Any tags that the rule is with. Mainly ATT&CK Techniques and Tactics  |
| detection_fields          | The fields the rule uses to detect the activity                       |
| detection_filters         | Any filters the rule may use                                          |
| detection_condition       | What causes the rule to trigger a positive detection                  |
+---------------------------+-----------------------------------------------------------------------+

Example
*********

Take the following rule, for example.

.. figure:: _static/sigma-rule.jpg
   :alt: Sigma Rule: WMI Persistence - Security
   :align: center

It is a rule to detect WMI Persistance from the Windows Security logs.

The script, analyzes the rule, and creates the following JSON.

.. figure:: _static/extracted-field-json.png
   :alt: Sigma Rule: WMI Persistence - Security
   :align: center

With this formatted output, the next step in the pipeline can now take place.


Scoring Dictionary
--------------------
