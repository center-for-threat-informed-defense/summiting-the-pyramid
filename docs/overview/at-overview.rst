Ambiguous Techniques Overview
==============================

.. figure:: ../_static/ATlogo.png
   :alt: AT logo
   :align: center
   :scale: 100%
 
Ambiguous Techniques focused on a core defensive problem: the observables of some ATT&CK techniques are not sufficient to determine malicious intent. The project defined an “ambiguous technique” as one whose observables are not sufficient to determine malicious intent with a preponderance of certainty, meaning defenders need more deliberate and conclusive detections to reduce false positives. To address this, the project centered on the concepts of intent (malicious vs. benign) and context (situational awareness that substantiates and clarifies the behavior of interest), and emphasized that detecting ambiguous techniques requires bringing in additional context beyond the technique’s basic observables.

To operationalize this, the project established :ref:`context-focused categories<Context>` that describe what kind of information defenders need to determine intent. A :ref:`Contextual Requirements Flowchart<Flowchart>` was developed to guide consistent categorization of techniques and to show how a technique can shift between context categories depending on what additional information is available. The project also documented co-occurring technique :ref:`chaining methods<Chaining Analytics>`: direct correlation (all conditions must be met) and loose correlation (threshold-based, e.g., distinct count of analytics firing)—to enable detections that are more robust and lower-noise than alerting on isolated activity.

Key accomplishments and deliverables included publishing a methodology for identifying ambiguous techniques and guidance on distinguishing malicious from benign activity, as well as publishing :ref:`robust analytics<analytics>` with associated co-occurring technique research. The project demonstrated example chained analytics that used both direct and loose correlations. Overall, the Ambiguous Techniques project provides defenders a structured way to understand ambiguous techniques in the defensive ecosystem, apply context-driven detection engineering methods to reduce false positives, and use the resulting documentation and example analytics to improve detection strategies and inform defensive posturing.

----------------------------------

The Ambiguous Techniques v2 project extended the original work to address a practical implementation question that emerged from Ambiguous Techniques: what are the minimum telemetry requirements needed to detect ambiguous techniques effectively, and how can defenders assess which telemetry sources are most robust for specific ambiguous-technique use cases. The project’s objective was to create a repeatable process for determining minimum telemetry requirements for detection, and to develop a confidence score-type approach (implemented as a scoring model) for telemetry sources as they relate to robustness and utility in detecting ambiguous techniques.

The project delivered a structured methodology to identify :ref:`minimum telemetry requirements<mintelreq>`. Building on this, the project established a :ref:`telemetry scoring approach<Telemetry Quality>` (referred to as Telemetry Quality) using a defined evaluation process with metrics spanning log source quality and technique-driven measures: Fidelity, Robustness, Cost, Noise Level, Coverage, Timeliness, and Context.

A major accomplishment of Ambiguous Techniques v2 was scaling this assessment to broader :ref:`use cases<Use Cases>` (groupings of techniques with similar objectives) and exploring automation via an AI/LLM retrieval-augmented, multi-step prompt process. The project documented an :ref:`AI-driven execution protocol<automation>` that is grounded in user-provided inputs and performs technique-by-technique scoring, averaging, and total score calculation. Final results were summarized across multiple use cases and published in our repository.

In conclusion, Ambiguous Techniques v2 provided defenders with a data-driven way to prioritize telemetry collection and capability investment by replacing subjective decisions with a quantitative scoring model tied to detection objectives. It also made detection engineering more actionable by identifying which log sources to ingest and configure first for high-value ambiguous-technique use cases. The project’s deliverables and results support more focused, context-rich, and lower-noise detections for ambiguous techniques, while also establishing a repeatable, extensible foundation for future work.
