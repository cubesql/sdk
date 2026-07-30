param(
    [Parameter(Mandatory = $true)][string]$DriverPath,
    [string]$Dsn,
    [string]$Server = "localhost",
    [int]$Port = 4430,
    [string]$User = "",
    [string]$Database = "",
    [ValidateSet("NONE", "AES128", "AES192", "AES256", "SSL", "SSL+AES128", "SSL+AES192", "SSL+AES256")]
    [string]$Encryption = "AES256",
    [ValidateSet("User", "System")][string]$Scope = "System"
)

$ErrorActionPreference = "Stop"
$resolved = (Resolve-Path $DriverPath).Path
$driverName = "CubeSQL ODBC Driver"
$base = if ([Environment]::Is64BitOperatingSystem -and $resolved -match "32") {
    "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\ODBC\ODBCINST.INI"
} else {
    "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\ODBC\ODBCINST.INI"
}

New-Item -Path "$base\$driverName" -Force | Out-Null
Set-ItemProperty -Path "$base\$driverName" -Name Driver -Value $resolved
Set-ItemProperty -Path "$base\$driverName" -Name Setup -Value $resolved
Set-ItemProperty -Path "$base\$driverName" -Name APILevel -Value "2"
Set-ItemProperty -Path "$base\$driverName" -Name ConnectFunctions -Value "YYN"
Set-ItemProperty -Path "$base\$driverName" -Name DriverODBCVer -Value "02.00"
Set-ItemProperty -Path "$base\$driverName" -Name FileUsage -Value "0"
Set-ItemProperty -Path "$base\ODBC Drivers" -Name $driverName -Value "Installed"

if ($Dsn) {
    $dsnBase = if ($Scope -eq "User") {
        "Registry::HKEY_CURRENT_USER\SOFTWARE\ODBC\ODBC.INI"
    } elseif ($base -match "WOW6432Node") {
        "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\ODBC\ODBC.INI"
    } else {
        "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\ODBC\ODBC.INI"
    }
    New-Item -Path "$dsnBase\$Dsn" -Force | Out-Null
    Set-ItemProperty -Path "$dsnBase\$Dsn" -Name Driver -Value $resolved
    Set-ItemProperty -Path "$dsnBase\$Dsn" -Name Server -Value $Server
    Set-ItemProperty -Path "$dsnBase\$Dsn" -Name Port -Value "$Port"
    Set-ItemProperty -Path "$dsnBase\$Dsn" -Name UID -Value $User
    Set-ItemProperty -Path "$dsnBase\$Dsn" -Name Database -Value $Database
    Set-ItemProperty -Path "$dsnBase\$Dsn" -Name Encryption -Value $Encryption
    New-Item -Path "$dsnBase\ODBC Data Sources" -Force | Out-Null
    Set-ItemProperty -Path "$dsnBase\ODBC Data Sources" -Name $Dsn -Value $driverName
}

Write-Host "Installed $driverName from $resolved"
