.. _Model Mapping Pages:

===================
Model Mapping Pages
===================

Our model defines five levels of analytic robustness and three columns of event
robustness. (See: :doc:`../definitions`) This section goes into deeper detail about how the
levels and columns are defined and how to map observables onto our model.

**Levels: Analytic Robustness Categories**

There are five levels that represent how difficult it is for an adversary to evade an
observable.

.. toctree::
    :maxdepth: 1

    technique
    implementations
    preexisting_tool
    adversary_tool
    ephemeral

**Columns: Host-Based Event Robustness Columns**

There are three columns that represent where event data originates within the OS.

.. toctree::
    :maxdepth: 1

    application
    user-mode
    kernel-mode

**Columns: Network Traffic Robustness Columns**

There are two columns that represent visibility into network traffic.

.. toctree::
    :maxdepth: 1

    payload
    header

For a quick search of an observable, please utilize the observables page.

.. toctree::
    :maxdepth: 1

    quicklevels
