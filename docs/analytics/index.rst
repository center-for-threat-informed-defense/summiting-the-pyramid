.. _analytics:

====================
Analytics Repository
====================

Robust Analytics
-----------------

The following examples demonstrate how to score and improve an analytic in accordance
with the Summiting the Pyramid methodology.

.. toctree::
    :maxdepth: 1

    access_token_manipulation
    adfind
    executable_download_webdav
    file_creation_date
    link_download_webdav
    remote_registry
    service_registry_permissions_weakness_check
    task_scheduling
    zeek_dce_rpc

Context-Aware Analytics
-------------------------------------------

The following examples demonstrate how to incorporate contextual requirements for ambiguous techniques in order to maximize robustness while reducing false positivies.

.. toctree::
    :maxdepth: 1

    archive_collected_data
    domain_account_discovery
    file_directory_discovery
    lsass_memory



.. _Scored Analytics:

Analytic Scoring Data
-------------------------------

There is also a published CSV file that contains analytics that have been scored with
the methodology: :download:`ScoredAnalytics <ScoredAnalytics_05062025.csv>`

**Score your own analytics in Sigma!** 

Sigma now has a tag to document the STP score of an analytic. `Checkout the
Sigma tags appendix to learn more
<https://github.com/SigmaHQ/sigma-specification/blob/main/appendix/sigma-tags-appendix.md#namespace-stp>`_.
