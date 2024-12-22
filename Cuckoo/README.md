#### Configuration Instructions for adding TIA to Cuckoo Sandbox

* Copy web/templates/analysis/tia.html

* Copy web/templates/analysis/static/_tia.html

* Edit web/templates/analysis/static/index.html

  * Add code (an example of this code modification is provided in the Modification Example folder):

```{% if config.tia and analysis.info.category == "file" %}
<li><a href="#static_tia_tab" data-toggle="tab">TIA</a></li>
{% endif %}

{% if config.tia %}
<div class="tab-pane fade" id="static_tia_tab">
    {% include "analysis/static/_tia.html" %}
</div>
{% endif %}
```

* Copy over /modules/processing/tia.py

* Make sure you are compiling tia.py in cuckoo.pyproj.

```
<Compile Include="modules\processing\tia.py" />
```

Also check content include in cuckoo.pyproj and add if missing.
```
<Content Include="web\templates\analysis\antivirus.html" />
<Content Include="web\templates\analysis\tia.html" />
<Content Include="web\templates\analysis\static\_antivirus.html" />
<Content Include="web\templates\analysis\static\_tia.html" />
```
add the following to config/processing.conf replicating the key with your assigned key:
```
[tia]
enabled = yes
key = 0123456789ABCD
```

* Cuckoo Sandbox will need to be restarted for changes to take effect. 
* You may also need to adjust the order in tia.py so the module runs after VirusTotal. See [commit](https://github.com/RandomRhythm/threatintelligenceaggregator/commit/82ba02044f0eb35ee2970646ae8f7de822bb96fd) for an example
