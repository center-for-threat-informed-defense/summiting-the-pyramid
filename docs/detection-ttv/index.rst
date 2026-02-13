Detection Evaluation & Validation
========================================

.. epigraph::

  We evaluate analytic depth, evasion resistance, and behavioral coverage to ensure detections operate high on the behavioral pyramid. Robust detections withstand variation, obfuscation, and environmental drift.

------------------------

.. raw:: html

   <div class="container">
     <h2>Detection Evaluation & Validation Key Components</h2>
     <div class="btn-group-vertical btn-block">
         <button type="button" class="btn btn-primary btn-block" data-toggle="collapse" data-target="#one">Analytic Validation</button>
         <div id="one" class="collapse">
       	   <br>Varifying the analytic fires when expected<br>
           <ul>
              <li><a href="https://attack.mitre.org/resources/learn-more-about-attack/training/threat-hunting/#mod5">ATT&CK Training: Threat Hunting & Detection Engineering</a></li>
           </ul>
         </div>
         <button type="button" class="btn btn-primary btn-block" data-toggle="collapse" data-target="#two">Behavioral Coverage Depth</button>
         <div id="two" class="collapse">
       	   <br>Assessing how high on the behavioral pyramid a detection operates<br>
           <ul>
              <li><a href="../detection-ttv/scoringanalytic">How to Score Resistance to Adversary Evasion</a></li>
              <li><a href="../detection-ttv/combiningobservables">Combining Observables</a></li>
              <li><a href="../examples/examplemappings">Example Mappings</a></li>
           </ul>
         </div>
         <button type="button" class="btn btn-primary btn-block" data-toggle="collapse" data-target="#three">Detection Strength Scoring</button>
         <div id="three" class="collapse">
       	   <br>Scoring detections based on behavioral depth and robustness<br>
           <ul>
              <li><a href="../levels/index">Summiting Level Definitions</a></li>
              <li><a href="../analytics/index">Scored Analytics</a></li>
           </ul>
         </div>
         <button type="button" class="btn btn-primary btn-block" data-toggle="collapse" data-target="#four">Performance & Stability Monitoring</button>
         <div id="four" class="collapse">
       	   <br>Monitoring detection health over time<br>
         </div>
     </div>
   </div>

--------------------------------------------------

.. toctree::
    :hidden:
    :maxdepth: 2

    ../levels/index
    combiningobservables
    scoringanalytic
