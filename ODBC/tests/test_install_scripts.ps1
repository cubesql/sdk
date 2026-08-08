<#
.SYNOPSIS
    Verifica install.ps1 e uninstall.ps1 contro il registro.

.DESCRIPTION
    Nessun test eseguiva questi script, e due difetti bloccanti stavano proprio
    li': l'acceleratore [ushort], che non esiste in Windows PowerShell 5.1e
    faceva morire lo script prima di scrivere qualunque cosa, e fRequest=1
    (ODBC_INSTALL_INQUIRY invece di ODBC_INSTALL_COMPLETE), che faceva
    restituire "riuscito" senza toccare il registro.

    La prova usa cartelle il cui nome suggerisce l'architettura SBAGLIATA: e' la
    condizione in cui la versione precedente, che deduceva l'architettura dal
    percorso, si registrava nel ramo errato.

    Serve l'elevazione perche' la registrazione di un driver scrive in HKLM.
    Senza, esce con 77, che CTest interpreta come "saltato".

    La registrazione preesistente viene salvata e ripristinata alla fine.
#>
[CmdletBinding()]
param(
    [string]$Driver64,
    [string]$Driver32,
    [string]$ScriptDir
)

$ErrorActionPreference = "Stop"
$SKIP = 77
$name    = "CubeSQL ODBC Driver"
$native  = "HKLM:\SOFTWARE\ODBC\ODBCINST.INI\$name"
$wow     = "HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBCINST.INI\$name"
$failures = 0

function Fail($msg) { Write-Host "FAIL: $msg"; $script:failures++ }
function Check($cond, $msg) { if (-not $cond) { Fail $msg } }

$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevated) {
    Write-Host "SALTATO: registrare un driver ODBC scrive in HKLM e servono privilegi elevati."
    Write-Host "         Rilancia da un prompt come amministratore per eseguire questo test."
    exit $SKIP
}

if (-not $ScriptDir) { $ScriptDir = Join-Path (Split-Path -Parent $PSScriptRoot) "windows" }
$install   = Join-Path $ScriptDir "install.ps1"
$uninstall = Join-Path $ScriptDir "uninstall.ps1"
Check (Test-Path $install)   "install.ps1 non trovato in $ScriptDir"
Check (Test-Path $uninstall) "uninstall.ps1 non trovato in $ScriptDir"
if ($failures) { exit 1 }

# --- salvataggio dello stato preesistente, per ripristinarlo alla fine ---
$saved = @()
foreach ($k in @($native, $wow)) {
    if (Test-Path $k) {
        $p = Get-ItemProperty $k
        $saved += [PSCustomObject]@{ Key = $k; Driver = $p.Driver }
    }
}
Write-Host "registrazioni preesistenti da ripristinare: $($saved.Count)"

# Volutamente SENZA -RemoveAll: quel parametro passa fRemoveDSN=TRUE a
# SQLRemoveDriver, che cancella tutte le sorgenti dati che usano il driver -
# comprese quelle dell'utente, che con un test non c'entrano nulla. Senza, ogni
# chiamata decrementa soltanto lo usage count, e la chiave sparisce quando
# arriva a zero: e' quello che serve qui, e non tocca i DSN di nessuno.
function Clear-Registration {
    foreach ($a in @("64", "32")) {
        for ($i = 0; $i -lt 8; $i++) {
            $k = if ($a -eq "64") { $native } else { $wow }
            if (-not (Test-Path $k)) { break }
            & $uninstall -Architecture $a *>$null
        }
    }
}

function Test-Arch($dll, $stagingName, $expectNative, $label) {
    if (-not $dll -or -not (Test-Path $dll)) {
        Write-Host "  $label : DLL non disponibile, salto"
        return
    }
    $staging = Join-Path $env:TEMP $stagingName
    New-Item -ItemType Directory -Force $staging | Out-Null
    Copy-Item $dll (Join-Path $staging "cubesqlodbc.dll") -Force

    Clear-Registration
    Check (-not (Test-Path $native)) "$label : il ramo nativo non e' pulito prima della prova"
    Check (-not (Test-Path $wow))    "$label : il ramo WOW6432Node non e' pulito prima della prova"

    # $LASTEXITCODE lo imposta solo un eseguibile nativo, e install.ps1 ne lancia
    # uno soltanto quando deve cambiare vista del registro: registrando un driver
    # della stessa architettura del processo non parte nulla di nativo e la
    # variabile resta quella di prima, cioe' $null in una sessione appena nata.
    # Confrontarla con 0 faceva fallire il ramo x64 e passare quello x86, dove il
    # rilancio in SysWOW64 la valorizza. Azzerarla prima rende valido il
    # controllo in entrambi i casi; gli errori veri arrivano come eccezioni,
    # perche' install.ps1 gira con $ErrorActionPreference = "Stop".
    $global:LASTEXITCODE = 0
    $why = $null
    try { & $install -DriverPath (Join-Path $staging "cubesqlodbc.dll") -Encryption NONE *>$null }
    catch { $why = $_.Exception.Message }
    if (-not $why -and $LASTEXITCODE -ne 0) { $why = "codice di uscita $LASTEXITCODE" }
    if ($why) { Fail "$label : install.ps1 non ha completato: $why" }

    $gotNative = Test-Path $native
    $gotWow    = Test-Path $wow
    if ($expectNative) {
        Check $gotNative      "$label : atteso nel ramo nativo, non c'e'"
        Check (-not $gotWow)  "$label : non atteso in WOW6432Node, invece c'e'"
        $key = $native
    } else {
        Check $gotWow             "$label : atteso in WOW6432Node, non c'e'"
        Check (-not $gotNative)   "$label : non atteso nel ramo nativo, invece c'e'"
        $key = $wow
    }

    if (Test-Path $key) {
        $p = Get-ItemProperty $key
        Check ($p.Driver -eq (Join-Path $staging "cubesqlodbc.dll")) "$label : Driver punta a '$($p.Driver)'"
        Check (-not [string]::IsNullOrWhiteSpace($p.Setup)) "$label : Setup vuoto, la finestra di configurazione sarebbe irraggiungibile"
        Check ($p.APILevel -eq "2")        "$label : APILevel = '$($p.APILevel)'"
        Check ($p.ConnectFunctions -eq "YYN") "$label : ConnectFunctions = '$($p.ConnectFunctions)'"
        Write-Host "  $label : registrato correttamente in $(Split-Path $key -Leaf)"
    }

    Clear-Registration
    Check (-not (Test-Path $native)) "$label : la disinstallazione non ha ripulito il ramo nativo"
    Check (-not (Test-Path $wow))    "$label : la disinstallazione non ha ripulito WOW6432Node"
    Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
}

try {
    # I nomi delle cartelle suggeriscono l'architettura sbagliata di proposito.
    Test-Arch $Driver64 "cs-pkg-x86-32bit" $true  "x64 da cartella 'x86-32bit'"
    Test-Arch $Driver32 "cs-pkg-amd64"     $false "Win32 da cartella 'amd64'"
}
finally {
    Clear-Registration
    foreach ($s in $saved) {
        if (Test-Path $s.Driver) {
            & $install -DriverPath $s.Driver -Encryption NONE *>$null
        }
    }
    $restored = @($saved | Where-Object { Test-Path $_.Key }).Count
    Write-Host "registrazioni ripristinate: $restored di $($saved.Count)"
}

if ($failures) { Write-Host "CubeSQL ODBC install-scripts: $failures controlli falliti"; exit 1 }
Write-Host "CubeSQL ODBC install-scripts: PASS"
exit 0
