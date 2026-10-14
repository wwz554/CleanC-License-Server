param([string]$ProjectName='cleanc-license-server',[switch]$RestoreSecrets,[switch]$SkipInstall)
$ErrorActionPreference='Stop'
$sourceRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Set-Location -LiteralPath $sourceRoot
if($ProjectName -notmatch '^[a-z0-9][a-z0-9-]{0,57}[a-z0-9]$'){throw 'Pages项目名称格式无效。'}
if(-not(Get-Command node -ErrorAction SilentlyContinue)){throw '请先安装Node.js 22或24 LTS。'}
if(-not $SkipInstall){& npm.cmd ci;if($LASTEXITCODE -ne 0){throw '依赖安装未完成。'}}
$wranglerPath=Join-Path $sourceRoot 'node_modules\wrangler\bin\wrangler.js'
if(-not(Test-Path -LiteralPath $wranglerPath)){throw '缺少Wrangler，请先运行一键构建。'}
& npm.cmd run build
if($LASTEXITCODE -ne 0){throw '编译未通过，未部署。'}
if($RestoreSecrets){
    & node (Join-Path $sourceRoot 'scripts\check-secret-backup.mjs')
    if($LASTEXITCODE -ne 0){throw '原始密钥备份校验失败，未上传Secret。'}
    $secretsFile=Join-Path $sourceRoot 'private-secrets\cloudflare-secrets.json'
    & node $wranglerPath pages secret bulk $secretsFile --project-name $ProjectName
    if($LASTEXITCODE -ne 0){throw 'Secret恢复未完成，请查看错误；不要重新生成原签名密钥。'}
}
& node $wranglerPath pages deploy public --project-name $ProjectName --branch main --commit-dirty=true
if($LASTEXITCODE -ne 0){throw '部署未完成。数据库和本地恢复文件未删除。'}
Write-Host '部署请求完成。请在Cloudflare确认生产部署成功并核对DB绑定及原域名。此脚本不导入或清空数据库。'
