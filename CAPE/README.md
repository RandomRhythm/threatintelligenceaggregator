### Configuration Instructions for adding TIA to CAPE Sandbox

* Copy web/templates/analysis/overview/_tia.html

* Edit web/templates/analysis/overview/index.html

  * Add code before statistics section:

```
{% if config.tia %}
    <hr />
    {% include "analysis/overview/_tia.html" %}
{% endif %}
```
<br>


add the following to config/processing.conf replicating the key with your assigned key:

```
[tia]
enabled = yes
key = 0123456789ABCD
```
<br>

* CAPE Sandbox will need to be restarted for changes to take effect. 
* You may also need to adjust the order in tia.py so the module runs after VirusTotal. See [commit](https://github.com/RandomRhythm/threatintelligenceaggregator/commit/82ba02044f0eb35ee2970646ae8f7de822bb96fd) for an example
