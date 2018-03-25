#### Configuration Instructions for adding TIA to Cuckoo Sandbox

* Copy templates/analysis/static/_tia.html

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
* Cuckoo Sandbox will need to be restarted for changes to take effect.