====================
Analytics Repository
====================

The following examples demonstrate how to score and improve an analytic in accordance
with the Summiting the Pyramid methodology.

.. toctree::
    :maxdepth: 1

    adfind
    task_scheduling
    service_registry_permissions_weakness_check
    access_token_manipulation
    executable_download_webdav
    link_download_webdav
    remote_registry
    file_creation_date
    zeek_dce_rpc

.. _Scored Analytics:

**Scored Analytics Repository:**

There is also a published CSV file that contains analytics that have been scored with
the methodology: :download:`ScoredAnalytics <Scored_Analytics_20230802.csv>`

**Submitting an Analytic:**

The Summiting team is looking for analytics which have been scored or improved by the
community for our Scored Analytics Repository.

If you are interested in contributing to our repository, please `submit a request
<https://github.com/center-for-threat-informed-defense/summiting-the-pyramid/issues/new?assignees=marvel90120&labels=analytic%2Cissue&projects=&template=analytic_submission.yml&title=%5BAnalytic-Submission%5D%3A+>`__
on GitHub with the following information:

* Analytic schema (Sigma, Splunk, Elastic, etc.)
* Log source (Windows process creation, file event, etc.)
* Detection analytic with detection logic (AND, OR)
* The score for your analytic with a brief explanation
* Scorer
