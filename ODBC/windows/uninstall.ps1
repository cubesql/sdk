param([ValidateSet("32", "64")][string]$Architecture = "64")
$base = if ($Architecture -eq "32") {
    "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\ODBC\ODBCINST.INI"
} else {
    "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\ODBC\ODBCINST.INI"
}
$name = "CubeSQL ODBC Driver"
Remove-Item -Path "$base\$name" -Recurse -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "$base\ODBC Drivers" -Name $name -ErrorAction SilentlyContinue
Write-Host "Uninstalled $name ($Architecture-bit)"
