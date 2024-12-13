Summiting the Pyramid |version|
===============================

.. figure:: _static/Summit_the_Pyramid_12.11.2024.png
   :alt: Summiting the Pyramid, Leveling Up Your Analytics
   :align: center

Summiting the Pyramid is a research project focused on engineering cyber analytics to
make adversary evasion more difficult. This project is created and maintained by the
`MITRE Center for Threat-Informed Defense <https://ctid.mitre.org/>`__ in futherance of
our mission to advance the state of the art and the state of the practice in
threat-informed defense globally.

.. important::
    **What's New In V2:**

    In version 2.0, we updated and improved the project in the following ways!

    * Exploring how detection accuracy relates to robustness yada yada. See: :ref:`what-is-robust-detection`
    * Introducing Detection Decomposition Diagrams (D3), a new way to visualize and identify observables which are accurate and resistant to adversary evasion. :ref:`Checkout some D3 examples here<D3>`.
    * New Summiting scoring models! We updated our :ref:`host-based model<Host-Based Columns>` to include host-based network events, and created a new :ref:`network traffic model<Network Traffic Columns>`.

.. toctree::
    :maxdepth: 2
    :caption: Contents

    overview
    introduction
    definitions
    levels/index
    booleanlogic
    examplemappings
    scoringanalytic
    analytics/index
    detection-components
    robustdetection
    D3

    futurework
    thanks
    changelog

Notice
------

© |copyright_years| MITRE Engenuity. Approved for public release. Document number(s)
|prs_numbers|.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
file except in compliance with the License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under
the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.

This project makes use of ATT&CK®: `ATT&CK Terms of Use
<https://attack.mitre.org/resources/terms-of-use/>`__
