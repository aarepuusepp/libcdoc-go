# Verify nested modules independently; root go test ./... does not traverse them.
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot
$work=Join-Path ([IO.Path]::GetTempPath()) ('libcdoc-cli-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$oldWork=$env:GOWORK
$env:GOWORK='off'
function Run($exe,$arguments){
 & $exe @arguments
 if($LASTEXITCODE){throw "$exe exited with $LASTEXITCODE"}
}
try{
 foreach($name in @('cdoc-cli','cdoc-test','cdoc-server-mock')){
  Write-Host "START $name module validation"
  Push-Location (Join-Path $PSScriptRoot $name)
  try{
   Run go @('mod','verify')
   Run go @('test','-mod=readonly','./...')
   Run go @('vet','-mod=readonly','./...')
   Run go @('build','-mod=readonly','-o',(Join-Path $work "$name.exe"),'.')
  }finally{Pop-Location}
  Write-Host "PASS $name module validation"
 }
 $cli=Join-Path $work 'cdoc-cli.exe'
 Push-Location (Join-Path $PSScriptRoot 'cdoc-cli')
 try{$expected=(go list -mod=readonly -m -f '{{.Version}}' github.com/aarepuusepp/libcdoc-go/v2).TrimStart('v')}finally{Pop-Location}
 $actual=(& $cli --version) -join ' '
 if($LASTEXITCODE -or $actual -ne "cdoc version $expected (libcdoc-go)"){throw "Unexpected CLI version: $actual"}
 $input=Join-Path $work 'test-ü.txt'
 $input2=Join-Path $work 'second.txt'
 [IO.File]::WriteAllText($input,'CDOC2 CLI roundtrip – public synthetic test',[Text.UTF8Encoding]::new($false))
 [IO.File]::WriteAllText($input2,'second public test',[Text.UTF8Encoding]::new($false))
 $key=Join-Path $work 'key.bin';$badKey=Join-Path $work 'wrong-key.bin'
 [IO.File]::WriteAllBytes($key,[byte[]](1..32))
 [IO.File]::WriteAllBytes($badKey,[byte[]](33..64))
 $container=Join-Path $work 'test.cdoc2';$output=Join-Path $work 'decrypted'
 Run $cli @('encrypt','-f',"$input,$input2",'-s',$key,'-c','2.0','-o',$container)
 Run $cli @('decrypt','-f',$container,'-s',$key,'-o',$output)
 foreach($file in @($input,$input2)){
  $restored=Join-Path $output (Split-Path $file -Leaf)
  if((Get-FileHash $file).Hash -ne (Get-FileHash $restored).Hash){throw "Plaintext mismatch: $file"}
 }
 $rejected=Join-Path $work 'rejected'
 & $cli decrypt -f $container -s $badKey -o $rejected
 if(!$LASTEXITCODE){throw 'Wrong key was accepted'}
 if((Test-Path $rejected) -and (Get-ChildItem $rejected -File -Recurse)){throw 'Wrong key released output'}
 Write-Host 'PASS CLI version, multi-file/unicode roundtrip and wrong-key rejection'
}finally{
 $env:GOWORK=$oldWork
 $resolved=[IO.Path]::GetFullPath($work)
 $temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
 if(!$resolved.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $resolved -Leaf) -notmatch '^libcdoc-cli-[0-9a-f]{32}$'){throw 'Unexpected temporary test path'}
 Remove-Item -LiteralPath $resolved -Recurse -Force
}
# The wrong-key probe intentionally leaves a nonzero native exit code.
# Return explicit success only after all checks and temporary-file cleanup pass.
exit 0
