param([string]$Database='cleanc-license')
$ErrorActionPreference='Stop'
$sourceRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Set-Location -LiteralPath $sourceRoot
if($Database -notmatch '^[A-Za-z0-9_-]{1,80}$'){throw '数据库名称格式无效。'}
$folder=Join-Path $sourceRoot 'private-secrets'
New-Item -ItemType Directory -Path $folder -Force | Out-Null
$backupSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $folder /inheritance:r /grant:r "*$($backupSid):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if($LASTEXITCODE -ne 0){throw '备份目录权限设置未完成。'}
$target=Join-Path $folder ('database-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.sql')
$wranglerPath=Join-Path $sourceRoot 'node_modules\wrangler\bin\wrangler.js'
& node $wranglerPath d1 export $Database --remote --output $target
if($LASTEXITCODE -ne 0){throw '数据库备份未完成。'}
Get-FileHash -LiteralPath $target -Algorithm SHA256 | Format-List
Write-Host '这是包含客户授权码和绑定的私密备份，请保存在安全位置。'
