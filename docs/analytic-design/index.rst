Analytic Design & Engineering
==============================

.. epigraph::

 We decompose adversary behavior into observable components and build robust, context-aware analytics that distinguish malicious activity from normal operations. Precision comes from modeling behavior, environment, and intent.

------------------------

.. raw:: html

   <div class="container">
     <h2>Analytic Design & Engineering Key Components</h2>
     <div class="btn-group-vertical btn-block">
         <button type="button" class="btn btn-primary btn-block" data-toggle="collapse" data-target="#one">Behavior Decomposition & Detection Hypothesis</button>
         <div id="one" class="collapse">
       	   <br>Breaking down adversary techniques into observable behaviors<br>
           <ul>
              <li><a href="../analytic-design/detection-diagram">Detection Decomposition Diagram</a></li>
              <li><a href="https://attack.mitre.org/resources/learn-more-about-attack/training/threat-hunting/">ATT&CK Training: Threat Hunting & Detection Engineering</a></li>
           </ul>
         </div>
         <button type="button" class="btn btn-primary btn-block" data-toggle="collapse" data-target="#two">Robust Analytic Design Patterns</button>
         <div id="two" class="collapse">
       	   <br>Reusable detection design approaches that survive small changes<br>
           <ul>
              <li><a href="../analytic-design/detection-components">Components of a Robust Detection</a></li>
              <li><a href="../analytic-design/robustdetection">How to Build a Robust Detection</a></li>
           </ul>
         </div>
         <button type="button" class="btn btn-primary btn-block" data-toggle="collapse" data-target="#three">Contextual Intent Inference</button>
         <div id="three" class="collapse">
       	   <br>Using environmental context to detemine whether behavior is malicious<br>
           <ul>
              <li><a href="../analytic-design/context">Using Context to Determine Intent</a></li>
           </ul>
         </div>
         <button type="button" class="btn btn-primary btn-block" data-toggle="collapse" data-target="#four">Precision Engineering & Signal Refinement</button>
         <div id="four" class="collapse">
       	   <br>Reducing false positives by improving behavioral modeling<br>
         </div>
         <button type="button" class="btn btn-primary btn-block" data-toggle="collapse" data-target="#five">Detection Logic Engineering</button>
         <div id="five" class="collapse">
       	   <br>Actual query construction and correlation logic<br>
           <ul>
              <li><a href="../analytic-design/chaining">Chaining Analytics</a></li>
              <li><a href="../analytics/index">Analytic Repository</a></li>
           </ul>
         </div>
         <button type="button" class="btn btn-primary btn-block" data-toggle="collapse" data-target="#six">Detection Lifecycle Management</button>
         <div id="six" class="collapse">
       	   <br>Maintaining detections as versioned, testable engineering artifacts<br>
         </div>
     </div>
   </div>

--------------------------------------------------

.. toctree::
    :maxdepth: 1
    :hidden:

    detection-components
    robustdetection
    detection-diagram
    context
    chaining
