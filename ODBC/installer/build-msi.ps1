<#
.SYNOPSIS
    Builds the CubeSQL ODBC driver MSI for one architecture.

.DESCRIPTION
    Requires the WiX .NET tool. Install it once with:
        dotnet tool install --global wix

    The architecture is taken from the PE header of the driver DLL, so the
    package platform can never disagree with the binary it carries.

.EXAMPLE
    .\build-msi.ps1 -DriverPath ..\build-vs\Release\cubesqlodbc.dll -OutputDir ..\dist
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$DriverPath,
    [string]$OutputDir = ".",
    [string]$Version
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $PSCommandPath
$repo = Split-Path -Parent $here

$resolved = (Resolve-Path -LiteralPath $DriverPath).Path

function Get-PeMachine {
    param([string]$Path)
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $reader = New-Object System.IO.BinaryReader($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw "$Path is not a Windows executable." }
        $stream.Position = 0x3C
        $stream.Position = $reader.ReadUInt32()
        if ($reader.ReadUInt32() -ne 0x00004550) { throw "$Path has no PE header." }
        return $reader.ReadUInt16()
    } finally { $stream.Dispose() }
}

switch (Get-PeMachine -Path $resolved) {
    0x014c  { $arch = "x86" }
    0x8664  { $arch = "x64" }
    0xAA64  { $arch = "arm64" }
    default { throw "Unsupported driver architecture in $resolved" }
}

if (-not $Version) {
    # Keep the package version in step with the driver's own resource.
    $Version = (Get-Item -LiteralPath $resolved).VersionInfo.FileVersion
    if (-not $Version) { throw "The driver has no version resource; pass -Version explicitly." }
}
# Windows Installer only understands a.b.c.d with numeric fields.
if ($Version -notmatch '^\d+(\.\d+){1,3}$') {
    throw "Version '$Version' is not a valid Windows Installer version."
}

$staging = Join-Path ([System.IO.Path]::GetTempPath()) ("cubesql-odbc-msi-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Force -Path $staging | Out-Null
try {
    Copy-Item (Join-Path $repo "README.md") $staging
    Copy-Item (Join-Path (Split-Path -Parent $repo) "LICENSE") $staging

    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    $output = Join-Path (Resolve-Path -LiteralPath $OutputDir).Path "cubesql-odbc-$arch-$Version.msi"

    Write-Host "Building $output ($arch, version $Version)"
    & wix build (Join-Path $here "cubesqlodbc.wxs") `
        -arch $arch `
        -d "DriverPath=$resolved" `
        -d "DocsPath=$staging" `
        -d "Version=$Version" `
        -o $output
    if ($LASTEXITCODE -ne 0) { throw "wix build failed with exit code $LASTEXITCODE" }
    Write-Host "Built $output"
    $output
} finally {
    Remove-Item -Recurse -Force $staging -ErrorAction SilentlyContinue
}
