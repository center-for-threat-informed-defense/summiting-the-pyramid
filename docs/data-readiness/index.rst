Telemetry Strategy & Readiness
================================

.. epigraph::

  Detection strength begins with the right telemetry. We prioritize high-value data collection, assess telemetry effectiveness, and ensure logging is configured to support robust behavioral inference — not just atomic matching.

------------------------

* Telemetry Capability Modeling

  *Understanding what a telemetry source can and cannot support from a detection perspective*

  * :ref:`Identifying minimum telemetry requirements<mintelreq>` to assess log source detection support

* Data Collection Prioritization
 
  *Choosing what telemetry to enable based on detection value*

  * :ref:`Calculating Telemetry Quality (TQ) score<Telemetry Quality>` to prioritize detection potential of log sources based on defined metrics

* Telemetry Effectiveness Assessment

  *Evaluating how well a telemetry source supports robust detection*

  * :ref:`Creating Detection Decomposition Diagrams<d3>` to evaluate overlapping analytic observables and assess gaps and redundancies

* Logging Standards & Instrumentation

  *Defining how telemetry must be configured to support analytics*

* Data Quality & Scheme Engineering

  *Ensuring data fields are reliable enough to build logic on*

* Entity & Context Modeling

  *Creating consistent identity, host, and lineage models so analytics can infer intent*


------------------------------

.. raw:: html

   <div class="container">
     <h2>Telemetry Strategy & Readiness Key Components</h2>
     <div class="btn-group-vertical">
         <button type="button" class="btn btn-primary" data-toggle="collapse" data-target="#one">Telemetry Capability Modeling</button>
         <div id="one" class="collapse">
       	   Understanding what a telemetry source can and cannot support from a detection perspective<br>
           <a class="bg-primary" href="../data-readiness/min-telemetry-reqs">Minimum Telemetry Requirements</a>
         </div>
         <button type="button" class="btn btn-primary" data-toggle="collapse" data-target="#two">Data Collection Prioritization</button>
         <div id="two" class="collapse">
       	   Choosing what telemetry to enable based on detection value
           <a class="btn btn-secondary" href="../data-readiness/telemetry-quality">Calculating Telemetry Quality (TQ) Score</a>
         </div>
         <button type="button" class="btn btn-primary" data-toggle="collapse" data-target="#three">Telemetry Effectiveness Assessment</button>
         <div id="three" class="collapse">
       	   Evaluating how well a telemetry source supports robust detection
           <a class="btn btn-secondary" href="../analytic-design/detection-diagram">Detection Decomposition Diagram</a>
         </div>
     </div>
   </div>

--------------------------------------------------




.. toctree::
    :maxdepth: 1
 
    min-telemetry-reqs
    telemetry-quality
