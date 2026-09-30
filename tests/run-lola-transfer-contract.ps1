param([string]$EvidenceRoot)
$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ine 'psclkfrm1dr3'){throw 'Wrong Dev'}
$n=Split-Path $PSScriptRoot -Parent
$s=[IO.File]::ReadAllText("$n\src\nvhttp.cpp")
$a=$s.IndexOf('  static constexpr std::uint64_t lola_upload_limit')
$z=$s.IndexOf('  class SunshineHTTPSServer', $a)
$out=$s.Substring($a,$z-$a)
$a=$s.IndexOf('  bool lola_safe_id(');$z=$s.IndexOf('  bool lola_active_client(', $a)
$out+=$s.Substring($a,$z-$a)
$a=$s.IndexOf('  void receiveLolaFile(');$z=$s.IndexOf('  void setup(', $a)
$out+=$s.Substring($a,$z-$a)
[IO.File]::WriteAllText("$EvidenceRoot\lola-transfer-under-test.inc",$out)
$env:PATH='C:\msys64\ucrt64\bin;'+$env:PATH
& 'C:\msys64\ucrt64\bin\g++.exe' -std=c++20 -O0 "-I$EvidenceRoot" "$n\tests\lola-transfer-contract.cpp" -o "$EvidenceRoot\lola-transfer-contract.exe"
if($LASTEXITCODE){throw 'Native contract compile failed'}
& "$EvidenceRoot\lola-transfer-contract.exe" "$EvidenceRoot\synthetic-native-transfer"
if($LASTEXITCODE){throw 'Native contract failed'}