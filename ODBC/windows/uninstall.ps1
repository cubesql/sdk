<#
.SYNOPSIS
    Unregisters the CubeSQL ODBC driver, and optionally removes a data source.

.DESCRIPTION
    Like install.ps1, this re-launches itself in a PowerShell of the matching
    bitness so it operates on the right ODBC registry view, and it goes through
    the ODBC installer API so the driver's usage count is respected: the driver
    is only really removed once the last product that registered it is gone.

.EXAMPLE
    .\uninstall.ps1 -Architecture 64

.EXAMPLE
    .\uninstall.ps1 -Architecture 32 -Dsn CubeSQLLocal
#>
[CmdletBinding()]
param(
    [ValidateSet("32", "64")][string]$Architecture = "64",
    [string]$Dsn,
    [ValidateSet("User", "System")][string]$Scope = "System",
    [switch]$RemoveAll,
    [switch]$NoRelaunch
)

$ErrorActionPreference = "Stop"
$driverName = "CubeSQL ODBC Driver"
$driverBits = [int]$Architecture
$processBits = if ([Environment]::Is64BitProcess) { 64 } else { 32 }

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if ($driverBits -ne $processBits) {
    if ($NoRelaunch) {
        throw "Cannot unregister a $driverBits-bit driver from a $processBits-bit process."
    }
    $shell = if ($driverBits -eq 32) {
        Join-Path $env:SystemRoot "SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
    } else {
        Join-Path $env:SystemRoot "Sysnative\WindowsPowerShell\v1.0\powershell.exe"
    }
    if (-not (Test-Path -LiteralPath $shell)) {
        throw "Cannot find a $driverBits-bit PowerShell at $shell"
    }
    $arguments = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", $PSCommandPath,
        "-Architecture", $Architecture,
        "-Scope", $Scope,
        "-NoRelaunch"
    )
    if ($Dsn) { $arguments += @("-Dsn", $Dsn) }
    if ($RemoveAll) { $arguments += "-RemoveAll" }
    & $shell $arguments
    exit $LASTEXITCODE
}

if (-not (Test-Elevated)) {
    throw ("Unregistering an ODBC driver writes to HKEY_LOCAL_MACHINE. " +
           "Re-run this script from a PowerShell started with 'Run as administrator'.")
}

Add-Type -Namespace CubeSQL -Name OdbcinstRemove -MemberDefinition @'
[DllImport("odbccp32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern bool SQLRemoveDriverW(string lpszDriver, bool fRemoveDSN, ref int lpdwUsageCount);

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
        $written = [ushort]0
        $text = New-Object System.Text.StringBuilder 512
        $rc = [CubeSQL.OdbcinstRemove]::SQLInstallerErrorW([ushort]$i, [ref]$code, $text, [ushort]512, [ref]$written)
        if ($rc -ne 0 -and $rc -ne 1) { break }
        $messages += ("({0}) {1}" -f $code, $text.ToString())
    }
    if ($messages.Count -eq 0) { return "no detail reported by the ODBC installer" }
    return ($messages -join "; ")
}

if ($Dsn) {
    # 6 = ODBC_REMOVE_SYS_DSN, 3 = ODBC_REMOVE_DSN
    $request = if ($Scope -eq "System") { [ushort]6 } else { [ushort]3 }
    $attributes = ("DSN=$Dsn" + "`0`0").ToCharArray()
    if ([CubeSQL.OdbcinstRemove]::SQLConfigDataSourceW([IntPtr]::Zero, $request, $driverName, $attributes)) {
        Write-Host "Removed $($Scope.ToLower()) data source '$Dsn'."
    } else {
        Write-Warning "Could not remove data source '$Dsn': $(Get-InstallerError)"
    }
}

$usage = 0
if ([CubeSQL.OdbcinstRemove]::SQLRemoveDriverW($driverName, [bool]$RemoveAll, [ref]$usage)) {
    if ($usage -gt 0) {
        Write-Host "'$driverName' ($Architecture-bit) still has usage count $usage; it remains registered."
    } else {
        Write-Host "Unregistered '$driverName' ($Architecture-bit)."
    }
} else {
    Write-Warning "Could not unregister '$driverName': $(Get-InstallerError)"
}
