<#
.SYNOPSIS
  Configure, build and test the project.

.EXAMPLE
  ./build.ps1                 # Release build + run all tests
  ./build.ps1 -Config Debug   # Debug build
  ./build.ps1 -Clean          # wipe build/ first
  ./build.ps1 -NoTest         # build only
  ./build.ps1 -Filter MinHeap # run only tests whose name contains "MinHeap"
#>
param(
    [ValidateSet('Debug', 'Release')] [string]$Config = 'Release',
    [switch]$Clean,
    [switch]$NoTest,
    [string]$Filter = ''
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$build = Join-Path $root 'build'

if ($Clean -and (Test-Path $build)) { Remove-Item $build -Recurse -Force }

if (-not (Test-Path (Join-Path $build 'CMakeCache.txt'))) {
    $generatorArgs = @()
    if ($IsLinux -or $IsMacOS) {
        # default generator
    } elseif (Test-Path "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019") {
        $generatorArgs = @('-G', 'Visual Studio 16 2019', '-A', 'x64')
    }
    cmake -S $root -B $build @generatorArgs "-DCMAKE_BUILD_TYPE=$Config"
    if ($LASTEXITCODE -ne 0) { throw 'cmake configure failed' }
}

cmake --build $build --config $Config
if ($LASTEXITCODE -ne 0) { throw 'build failed' }

if (-not $NoTest) {
    $exe = Join-Path $build "$Config/loganalyzer_tests.exe"
    if (-not (Test-Path $exe)) { $exe = Join-Path $build 'loganalyzer_tests' }
    & $exe $Filter
    if ($LASTEXITCODE -ne 0) { throw 'tests failed' }
}
