<#
.SYNOPSIS
  Compile and run a subset of the tests in an isolated temp directory, so several
  people (or agents) can check their own modules at once without sharing build/.

.EXAMPLE
  ./tools/quick.ps1 -Tag heap -Files tests/min_heap_test.cpp
  ./tools/quick.ps1 -Tag parser -Files src/log_parser.cpp,tests/log_parser_test.cpp -Filter Parser
  ./tools/quick.ps1 -Tag probe -Files C:\Temp\my_probe_test.cpp   # absolute paths are fine

  tests/test_main.cpp and src/log_entry.cpp are always linked in. List every other .cpp
  your tests need (implementation files AND test files). Headers are found via include/ and tests/.
#>
param(
    [Parameter(Mandatory)] [string]$Tag,
    [Parameter(Mandatory)] [string[]]$Files,
    [string]$Filter = '',
    [switch]$DebugBuild,
    [switch]$Asan
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path $vcvars)) { throw "vcvars64.bat not found at $vcvars" }

$out = Join-Path $env:TEMP "la-quick\$Tag"
if (Test-Path $out) { Remove-Item $out -Recurse -Force }
New-Item -ItemType Directory $out | Out-Null

$all = @('tests/test_main.cpp', 'src/log_entry.cpp') + $Files
$resolved = $all | ForEach-Object {
    if ([System.IO.Path]::IsPathRooted($_)) { $_ } else { Join-Path $root $_ }
} | Select-Object -Unique
foreach ($f in $resolved) { if (-not (Test-Path $f)) { throw "source not found: $f" } }

$opt = if ($DebugBuild) { '/Od /Zi /RTC1' } else { '/O2' }
$asanFlag = if ($Asan) { '/fsanitize=address /Zi' } else { '' }
$srcList = ($resolved | ForEach-Object { '"' + $_ + '"' }) -join ' '

$bat = Join-Path $out 'build.bat'
@"
@echo off
call "$vcvars" >nul 2>&1
cl /nologo /std:c++17 /EHsc /W4 /wd4127 /utf-8 $opt $asanFlag /Fd"$out\\" /D_CRT_SECURE_NO_WARNINGS /I"$root\include" /I"$root\tests" /Fo"$out\\" /Fe"$out\quick.exe" $srcList
"@ | Set-Content $bat -Encoding ascii

$ErrorActionPreference = 'Continue'   # cl writes warnings to stdout; don't let stray stderr abort us
cmd /c "`"$bat`""
$compileExit = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($compileExit -ne 0) { throw 'compile failed' }

& "$out\quick.exe" $Filter
if ($LASTEXITCODE -ne 0) { throw 'tests failed' }
