$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
New-Item -ItemType Directory -Force -Path css | Out-Null
New-Item -ItemType Directory -Force -Path assets\data | Out-Null
New-Item -ItemType Directory -Force -Path font | Out-Null
Copy-Item ..\css\* css\ -Recurse -Force
Copy-Item ..\assets\data\* assets\data\ -Recurse -Force
Copy-Item ..\font\* font\ -Recurse -Force
Copy-Item ..\fanap.png .\ -Force
Copy-Item ..\favicon.ico .\ -Force
Copy-Item ..\manifest.json .\ -Force
Copy-Item ..\icon-192.svg .\ -Force
Copy-Item ..\icon-512.svg .\ -Force