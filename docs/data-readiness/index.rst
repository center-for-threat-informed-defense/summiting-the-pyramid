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

   <div class="btn-group">
     <button type="button" class="btn btn-primary">Apple</button>
     <button type="button" class="btn btn-primary">Samsung</button>
     <div class="btn-group">
       <button type="button" class="btn btn-primary dropdown-toggle" data-toggle="dropdown">
       Sony <span class="caret"></span></button>
       <ul class="dropdown-menu" role="menu">
         <li><a href="#">Tablet</a></li>
         <li><a href="#">Smartphone</a></li>
       </ul>
     </div>
   </div>

   <button data-toggle="collapse" data-target="#demo">Collapsible</button>
   <div id="demo" class="collapse">
   Lorem ipsum dolor text....
   </div>

--------------------------------------------------




.. toctree::
    :maxdepth: 1
 
    min-telemetry-reqs
    telemetry-quality
