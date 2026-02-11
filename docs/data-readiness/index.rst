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
     <h3>Telemetry Strategy & Readiness</h3>
     <div class="row">
       <div class="col-md-3">
         <ul class="nav nav-pills nav-stacked">
           <li class="active"><a href="#">Telemetry Capability Modeling</a></li>
           <li><a href="/../data-readiness/min-telemetry-reqs">Minimum Telemetry Requirements</a></li>
         </ul>
       </div>
       <div class="col-md-3">
         <ul class="nav nav-pills nav-stacked">
           <li class="active"><a href="#">Data Collection Prioritization</a></li>
           <li><a href="/data-readiness/telemetry-quality.rst">Telemetry Quality (TQ) Scoring</a></li>
         </ul>
       </div>
       <div class="col-md-3">
         <ul class="nav nav-pills nav-stacked">
           <li class="active"><a href="#">Telemetry Effectiveness Assessment</a></li>
           <li><a href="../analytic-design/detection-diagram.rst">Detection Decomposition Diagrams</a></li>
         </ul>
       </div>
       <div class="col-md-3">
         <ul class="nav nav-pills nav-stacked">
           <li class="active"><a href="#">Logging Standards & Instrumentation</a></li>
         </ul>
       </div>
       <div class="col-md-3">
         <ul class="nav nav-pills nav-stacked">
           <li class="active"><a href="#">Data Quality & Scheme Engineering</a></li>
         </ul>
       </div>
         </ul>
       </div>
       <div class="col-md-3">
         <ul class="nav nav-pills nav-stacked">
           <li class="active"><a href="#">Entity & Context Modeling</a></li>
         </ul>
       </div>
       <div class="clearfix visible-lg"></div>
     </div>
   </div>

--------------------------------------------------

.. raw:: html

   <ul class="nav nav-tabs">
     <li class="active"><a href="#">Home</a></li>
     <li><a href="#">Menu 1</a></li>
     <li><a href="#">Menu 2</a></li>
     <li><a href="#">Menu 3</a></li>
   </ul>


.. toctree::
    :maxdepth: 1
 
    min-telemetry-reqs
    telemetry-quality
