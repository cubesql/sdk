<#
.SYNOPSIS
    Registers the CubeSQL ODBC driver, and optionally creates a data source.

.DESCRIPTION
    The architecture of the driver is read from the PE header of the DLL itself
    rather than guessed from its path, and the script re-launches itself in a
    PowerShell of the matching bitness before touching the registry. That is
    what makes a 32-bit driver land in the 32-bit ODBC registry view: the
    previous version tested the path for the substring "32", so the official
    32-bit package (whose folder is named "x86") registered itself as 64-bit.

    Registration goes through the ODBC installer API rather than raw registry
    writes, so the driver's usage count is maintained and uninstalling one
    product cannot silently unregister the driver another product still needs.

.EXAMPLE
    .\install.ps1 -DriverPath .\cubesqlodbc.dll

.EXAMPLE
    .\install.ps1 -DriverPath .\cubesqlodbc.dll -Dsn CubeSQLLocal `
        -Server db.example.com -Port 4430 -User admin -Database app.db
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$DriverPath,
    [string]$Dsn,
    [string]$Description = "",
    [string]$Server = "localhost",
    [int]$Port = 4430,
    [string]$User = "",
    [string]$Database = "",
    [ValidateSet("NONE", "AES128", "AES192", "AES256", "SSL", "SSL+AES128", "SSL+AES192", "SSL+AES256")]
    [string]$Encryption = "AES256",
    [int]$Timeout = 12,
    [ValidateSet("User", "System")][string]$Scope = "System",
    # Set internally when the script re-launches itself; do not pass by hand.
    [switch]$NoRelaunch
)

$ErrorActionPreference = "Stop"
$driverName = "CubeSQL ODBC Driver"

function Get-PeMachine {
    param([string]$Path)
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $reader = New-Object System.IO.BinaryReader($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw "$Path is not a Windows executable." }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadUInt32()
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw "$Path has no PE header." }
        return $reader.ReadUInt16()
    } finally {
        $stream.Dispose()
    }
}

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$resolved = (Resolve-Path -LiteralPath $DriverPath).Path
if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
    throw "Driver not found: $resolved"
}

$machine = Get-PeMachine -Path $resolved
switch ($machine) {
    0x014c { $driverBits = 32; $driverArch = "x86" }
    0x8664 { $driverBits = 64; $driverArch = "x64" }
    0xAA64 { $driverBits = 64; $driverArch = "arm64" }
    default { throw ("Unsupported driver architecture 0x{0:X4} in {1}" -f $machine, $resolved) }
}

$processBits = if ([Environment]::Is64BitProcess) { 64 } else { 32 }
Write-Host "Driver:       $resolved"
Write-Host "Architecture: $driverArch ($driverBits-bit)"

# The ODBC installer API writes to the registry view of the calling process, so
# a 32-bit driver has to be registered from a 32-bit PowerShell.
if ($driverBits -ne $processBits) {
    if ($NoRelaunch) {
        throw "Cannot register a $driverBits-bit driver from a $processBits-bit process."
    }
    if (-not [Environment]::Is64BitOperatingSystem -and $driverBits -eq 64) {
        throw "This is a 32-bit version of Windows; it cannot use a 64-bit ODBC driver."
    }
    $host32 = Join-Path $env:SystemRoot "SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
    $host64 = Join-Path $env:SystemRoot "Sysnative\WindowsPowerShell\v1.0\powershell.exe"
    $shell = if ($driverBits -eq 32) { $host32 } else { $host64 }
    if (-not (Test-Path -LiteralPath $shell)) {
        throw "Cannot find a $driverBits-bit PowerShell at $shell"
    }
    Write-Host "Re-launching in $driverBits-bit PowerShell to use the matching registry view..."
    $arguments = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", $PSCommandPath,
        "-DriverPath", $resolved,
        "-Scope", $Scope,
        "-Encryption", $Encryption,
        "-Server", $Server,
        "-Port", $Port,
        "-Timeout", $Timeout,
        "-NoRelaunch"
    )
    if ($Dsn) { $arguments += @("-Dsn", $Dsn) }
    if ($Description) { $arguments += @("-Description", $Description) }
    if ($User) { $arguments += @("-User", $User) }
    if ($Database) { $arguments += @("-Database", $Database) }
    & $shell $arguments
    exit $LASTEXITCODE
}

if (-not (Test-Elevated)) {
    throw ("Registering an ODBC driver writes to HKEY_LOCAL_MACHINE. " +
           "Re-run this script from a PowerShell started with 'Run as administrator'.")
}

Add-Type -Namespace CubeSQL -Name Odbcinst -MemberDefinition @'
[DllImport("odbccp32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern bool SQLInstallDriverExW(
    char[] lpszDriver, string lpszPathIn,
    System.Text.StringBuilder lpszPathOut, ushort cbPathOutMax, out ushort pcbPathOut,
    ushort fRequest, ref int lpdwUsageCount);

[DllImport("odbccp32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern bool SQLConfigDataSourceW(
    IntPtr hwndParent, ushort fRequest, string lpszDriver, char[] lpszAttributes);

[DllImport("odbccp32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern short SQLInstallerErrorW(
    ushort iError, out int pfErrorCode,
    System.Text.StringBuilder lpszErrorMsg, ushort cbErrorMsgMax, out ushort pcbErrorMsg);
'@

function Get-InstallerError {
    $messages = @()
    for ($i = 1; $i -le 8; $i++) {
        $code = 0
        $written = [uint16]0
        $text = New-Object System.Text.StringBuilder 512
        $rc = [CubeSQL.Odbcinst]::SQLInstallerErrorW([uint16]$i, [ref]$code, $text, [uint16]512, [ref]$written)
        if ($rc -ne 0 -and $rc -ne 1) { break }
        $messages += ("({0}) {1}" -f $code, $text.ToString())
    }
    if ($messages.Count -eq 0) { return "no detail reported by the ODBC installer" }
    return ($messages -join "; ")
}

# The installer API takes a NUL-separated, double-NUL terminated key list.
function ConvertTo-OdbcList {
    param([string[]]$Entries)
    return (($Entries -join "`0") + "`0`0").ToCharArray()
}

$driverEntries = @(
    $driverName,
    "Driver=$resolved",
    "Setup=$resolved",
    "APILevel=2",
    "ConnectFunctions=YYN",
    "DriverODBCVer=03.00",
    "SQLLevel=0",
    "FileUsage=0"
)

$pathOut = New-Object System.Text.StringBuilder 512
$pathLen = [uint16]0
$usage = 0
$ok = [CubeSQL.Odbcinst]::SQLInstallDriverExW(
    (ConvertTo-OdbcList $driverEntries), $null,
    $pathOut, [uint16]512, [ref]$pathLen,
    [uint16]2,          # ODBC_INSTALL_COMPLETE (2; 1 e' ODBC_INSTALL_INQUIRY, che non scrive nulla)
    [ref]$usage)
if (-not $ok) {
    throw "Registering '$driverName' failed: $(Get-InstallerError)"
}
Write-Host "Registered '$driverName' ($driverArch), usage count $usage."

if ($Dsn) {
    $dsnEntries = @(
        "DSN=$Dsn",
        "Server=$Server",
        "Port=$Port",
        "UID=$User",
        "Database=$Database",
        "Encryption=$Encryption",
        "Timeout=$Timeout",
        "Description=$Description"
    )
    # 4 = ODBC_ADD_SYS_DSN, 1 = ODBC_ADD_DSN
    $request = if ($Scope -eq "System") { [uint16]4 } else { [uint16]1 }
    $ok = [CubeSQL.Odbcinst]::SQLConfigDataSourceW(
        [IntPtr]::Zero, $request, $driverName, (ConvertTo-OdbcList $dsnEntries))
    if (-not $ok) {
        throw "Creating the $Scope data source '$Dsn' failed: $(Get-InstallerError)"
    }
    Write-Host "Created $($Scope.ToLower()) data source '$Dsn'."
    Write-Host "Passwords are never stored in a data source; supply PWD when connecting."
}
