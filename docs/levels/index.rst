.. _Model Mapping Pages:

===================
Model Mapping Pages
===================

When developing the Summiting the Pyramid Project, we needed to determine how to group different observables and sensor data, or parts of an analytic, and how to 
rank them. Currently, we have described these levels as the **Difficulty of Bypassing Analytic Observables**.  The following pages document the levels we have with observables.

**Levels: Analytic Robustness Categories**
There are five levels which are grouped based on how difficult it is for an adversary to evade the analytic observable. 

.. toctree::
    :maxdepth: 1

    technique
    implementations
    preexisting_tool
    adversary_tool
    ephemeral

**Columns: Event Robustness Categories**
There are currently three columns which describe event data based on their visibility into the OS. These may be similar to a sensor. However, due to where they are triggered in the OS, these are currently focusing on event robustness. This can change in the future due to ever growing sensors and the type of data they gather.

.. toctree::
    :maxdepth: 1

    application
    user-mode
    kernel-mode

For a quick search of an observable, please utilize the observables page.

.. toctree::
    :maxdepth: 1

    quicklevels