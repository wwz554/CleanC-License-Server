param()
$ErrorActionPreference='Stop'
$sourceRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Set-Location -LiteralPath $sourceRoot
if(-not(Get-Command node -ErrorAction SilentlyContinue)){throw '请先安装Node.js 22或24 LTS，然后重新打开PowerShell。'}
& npm.cmd ci
if($LASTEXITCODE -ne 0){throw 'npm ci未完成，请检查网络。'}
& npm.cmd run build
if($LASTEXITCODE -ne 0){throw '服务源码编译或HTML/JS语法检查未通过。'}
Write-Host '授权服务构建完成。尚未部署或更改数据库。'
