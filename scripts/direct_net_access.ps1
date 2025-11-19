$webClient = New-Object System.Net.WebClient
$url = "http://192.168.0.21/read.cgi?variable=Sys.Ver"
$response = $webClient.DownloadString($url)
Write-Host $response