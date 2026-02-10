Ambiguous Techniques Project
=============================

**Determining Malicious Intent for Ambiguous Techniques**

For :ref:`ambiguous techniques<AT Definition>`, invariant behaviors overlap
significantly between malicious and benign implementations, and so more
:ref:`context<Context Definition>` is needed to differentiate malicious
:ref:`intent<Intent Definition>` and behavior, otherwise detection analytics
risk drowning in false positives.  There is also a need when trying to identify
differentiators to maintain as high a level of robustness as possible, so that
you don't render the analytic ineffective in trying to gain a higher level of
precision.  

This theoretical challenge of determining intent for ambiguous techniques led us to our next phase of research: developing a quantitative model to score telemetry sources on their ability to provide this very context. See our full Telemetry Quality (TQ) scoring methodology and results to learn how we put these principles into practice
