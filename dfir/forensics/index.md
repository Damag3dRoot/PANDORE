## Artifact locations

A number of forensic artifacts are known for a number of operating systems.

A large number of these are covered on the Digital Forensics Artifact Repository, and can be ingested both by humans and systems given the standard YAML format.

-   [ForensicArtifacts](https://github.com/ForensicArtifacts/artifacts/tree/master/data)

### Get an object of forensic artifacts

```
$WindowsArtifacts=$(curl https://raw.githubusercontent.com/ForensicArtifacts/artifacts/master/data/windows.yaml)
$obj = ConvertFrom-Yaml $WindowsArtifacts.Content -AllDocuments
```

Now that it is stored within a format we can use the below will give us information at a glance.

```
$count=0;
foreach ($Artifact in $obj){
$Artifacts = [pscustomobject][ordered]@{
	Name = $obj.name[$count]
	Description = $obj.doc[$count]
	References = $obj.urls[$count]
	Attributes = $obj.sources.attributes[$count]
}
$count++;
$Artifacts | FL;
}
```

### Query object for relevant registry keys:

```
$obj.sources.attributes.keys|Select-String "HKEY"
$obj.sources.attributes.key_value_pairs
```

### Query object for relevant file paths:

```
$obj.sources.attributes.paths
```



















