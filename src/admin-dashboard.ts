import type { Env } from './worker';

const encoder = new TextEncoder();

function b64url(data: ArrayBuffer | Uint8Array): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function hmac(secret: string, text: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return b64url(await crypto.subtle.sign('HMAC', key, encoder.encode(text)));
}

function getCookie(request: Request, name: string): string {
  return (request.headers.get('cookie') || '')
    .split(/;\s*/)
    .find(value => value.startsWith(name + '='))
    ?.slice(name.length + 1) || '';
}

async function csrfToken(request: Request, env: Env): Promise<string> {
  return hmac(env.SESSION_SECRET, `csrf:${getCookie(request, 'cleanc_session')}`);
}

function renderDashboard(csrf: string): string {
  const csrfLiteral = JSON.stringify(csrf);
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CleanC License 管理后台</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#17233b;background:radial-gradient(circle at 5% 8%,#d9efff,transparent 34%),radial-gradient(circle at 92% 4%,#eadfff,transparent 38%),linear-gradient(135deg,#f8fbff,#eef4ff);min-height:100vh}.glass{background:rgba(255,255,255,.68);backdrop-filter:blur(28px) saturate(150%);border:1px solid rgba(255,255,255,.88);box-shadow:0 20px 60px rgba(43,72,140,.12),inset 0 1px 0 #fff;border-radius:24px}.app{min-height:100vh;padding:20px}.side{position:fixed;top:20px;bottom:20px;width:230px;padding:22px;display:flex;flex-direction:column}.brand{display:flex;align-items:center;gap:10px}.logo{width:44px;height:44px;border-radius:15px;display:grid;place-items:center;font-size:20px;font-weight:800;color:#fff;background:linear-gradient(145deg,#4a8cff,#765cff)}.nav{margin-top:22px}.btn{border:0;border-radius:13px;padding:10px 14px;cursor:pointer;font-weight:650;font:inherit}.btn:disabled{opacity:.58;cursor:not-allowed}.nav-btn{display:block;width:100%;text-align:left;margin:7px 0;background:transparent;color:#58667e}.nav-btn.active{background:#ffffffd9;color:#315fc5}.primary{background:linear-gradient(135deg,#4d88ff,#735cff);color:#fff}.secondary{background:#eef3ff;color:#375baf}.danger{background:#fff0f2;color:#c73555}.success{background:#ecf9f1;color:#24794a}.logout{margin-top:auto;width:100%}.main{margin-left:250px}.muted{color:#72809a}input,select{font:inherit;width:100%;padding:12px 14px;border:1px solid #dce5f4;border-radius:13px;background:#ffffffdf}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.row>*{flex:1}.row .btn{flex:0 0 auto}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.card,.panel{padding:20px}.panel{margin-top:16px}.stat b{font-size:30px}.section{display:none}.section.active{display:block}.hidden{display:none!important}.notice{padding:12px 14px;border-radius:13px;background:#eef4ff;color:#4c628f;margin:12px 0}.error{color:#b83250}.ok{color:#24794a}.status{min-height:20px;margin-top:10px}table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:10px 8px;border-bottom:1px solid #e4eaf3;vertical-align:top}code{background:#eef3ff;padding:3px 6px;border-radius:7px;word-break:break-all}.actions{display:flex;gap:6px;flex-wrap:wrap;align-items:flex-start}.more-wrap{position:relative;display:inline-block}.more-wrap summary{list-style:none}.more-wrap summary::-webkit-details-marker{display:none}.more-btn{min-width:42px;text-align:center;padding:8px 11px}.more-menu{position:absolute;right:0;top:calc(100% + 6px);z-index:30;min-width:120px;padding:6px;background:#fff;border:1px solid #e2e8f2;border-radius:12px;box-shadow:0 14px 36px rgba(43,72,140,.18)}.more-menu button{display:block;width:100%;margin:0;padding:9px 10px;text-align:left;border:0;border-radius:9px;background:transparent;cursor:pointer;font:inherit}.more-menu button:hover{background:#f3f6fb}.more-menu .restore-item{color:#315fc5}.more-menu .danger-item{color:#c73555}.pill{display:inline-block;padding:3px 8px;border-radius:999px;background:#eef3ff;color:#375baf;font-size:12px}.toolbar{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap}.compact-panel{padding:14px 16px;margin-top:8px}.compact-panel .notice{padding:8px 11px;margin:0 0 10px;font-size:13px}.compact-panel input,.compact-panel select{padding:9px 11px}.compact-panel .btn{padding:9px 13px}.compact-panel .status{margin-top:6px}.list-panel{padding:14px 16px}.list-tools{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:10px}.list-tools input{min-width:230px;flex:1}.list-tools select{width:auto;min-width:125px}.list-tools .btn{flex:0 0 auto}.table-wrap{overflow:auto}.pager{display:flex;justify-content:flex-end;align-items:center;gap:8px;padding-top:12px}.pager .btn{padding:8px 12px}.page-info{min-width:150px;text-align:center;color:#6c7890;font-size:13px}@media(max-width:900px){.side{position:static;width:auto;margin-bottom:14px}.main{margin-left:0}.grid{grid-template-columns:repeat(2,1fr)}.app{padding:12px}.logout{margin-top:16px}}@media(max-width:560px){.grid{grid-template-columns:1fr}.row>*{flex-basis:100%}}

:root{color-scheme:light}.app{max-width:1680px;margin:auto}.main{padding:6px 12px 36px}.glass{-webkit-backdrop-filter:blur(32px) saturate(155%);backdrop-filter:blur(32px) saturate(155%);box-shadow:0 16px 48px #273e6510,inset 0 1px 0 #ffffffed}.side{background:#ffffff80}.panel{background:#ffffffc7}.btn{min-height:44px;transition:transform .18s ease,box-shadow .18s ease,background .18s ease;border:1px solid #ffffff70;box-shadow:inset 0 1px 0 #ffffff70}.btn:hover:not(:disabled){transform:translateY(-1px);box-shadow:0 5px 16px #24487d20,inset 0 1px 0 #fff}.btn:active:not(:disabled){transform:scale(.98)}.btn:focus-visible,input:focus-visible,select:focus-visible,summary:focus-visible{outline:3px solid #4d88ff;outline-offset:3px}.primary{background:linear-gradient(150deg,#4088f5,#2866d4)}h2{font-size:30px;letter-spacing:-.8px;margin-bottom:8px}th{font-size:12px;color:#63738a;white-space:nowrap}td{padding:16px 8px}.copy-key{display:flex;gap:8px;align-items:center}.copy-key code{font-size:12px}.copy-btn{padding:6px 10px;white-space:nowrap}.status{overflow-wrap:anywhere}.pager{flex-wrap:wrap}.list-tools input{min-width:160px}.row input,.row select{min-width:140px}.row .btn{min-width:100px}.pill.expired{background:#f0f1f4;color:#656a75}.pill.active{background:#e5f5ed;color:#20724b}.pill.disabled{background:#fff0f2;color:#ab3450}
@media(max-width:900px){.side{padding:16px}.nav{display:flex;gap:6px;overflow-x:auto;margin-top:14px}.nav-btn{width:auto;flex:0 0 auto;text-align:center;margin:0}.logout{width:auto;align-self:flex-end;margin-top:10px}.main{padding:0 0 24px}}
@media(max-width:600px){.app{padding:10px}.panel{padding:16px;border-radius:22px}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.card{padding:16px}.stat b{font-size:28px}.list-tools>*{flex:1 1 42%!important;min-width:0!important}.list-tools input{flex-basis:100%!important}input,select{font-size:16px}.table-wrap table,.table-wrap tbody,.table-wrap tr,.table-wrap td{display:block}.table-wrap thead{display:none}.table-wrap tr{padding:12px;border:1px solid #dee5ef;border-radius:16px;margin-bottom:12px;background:#ffffffa8}.table-wrap td{padding:8px 0;border:0;overflow-wrap:anywhere}.table-wrap td:before{content:attr(data-label);display:block;font-size:11px;color:#6c7890;margin-bottom:5px}.table-wrap{overflow:visible}.copy-key{flex-wrap:wrap}.copy-key code{font-size:13px}.more-menu{right:auto;left:0}.pager{justify-content:center}.page-info{order:3;flex-basis:100%}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{transition:none!important;animation:none!important}.btn:hover:not(:disabled),.btn:active:not(:disabled){transform:none}}
@media(prefers-contrast:more){.glass,.panel{background:#fff}.muted,th{color:#39465a}.btn,input,select{border-color:#65748a}}
</style>
</head>
<body>
<div class="app">
<aside class="side glass">
<div class="brand"><div class="logo">C</div><b>CleanC</b></div>
<div class="nav">
<button class="btn nav-btn active" data-tab="dashboard">仪表盘</button>
<button class="btn nav-btn" data-tab="licenses">授权管理</button>
<button class="btn nav-btn" data-tab="devices">设备管理</button>
<button class="btn nav-btn" data-tab="logs">操作日志</button>
<button class="btn nav-btn" data-tab="settings">设置</button>
</div>
<button id="logoutBtn" class="btn secondary logout">退出登录</button>
</aside>
<main class="main">
<div class="toolbar"><div><h2 id="title">仪表盘</h2><p class="muted">CleanC 授权服务管理中心</p></div><div id="globalStatus" role="status" aria-live="polite" class="status muted"></div></div>
<section id="dashboard" class="section active"><div class="grid"><div class="card glass stat">总授权<br><b id="sTotal">-</b></div><div class="card glass stat">有效授权<br><b id="sActive">-</b></div><div class="card glass stat">已禁用<br><b id="sDisabled">-</b></div><div class="card glass stat">绑定设备<br><b id="sDevices">-</b></div></div></section>
<section id="licenses" class="section"><div class="panel glass compact-panel"><div class="notice"><b>生成授权：</b>自定义时只输入字母/数字即可，点击生成后自动格式化为 CLC-XXXX-XXXX…；留空则随机生成标准授权码。</div><div class="row"><input id="customKey" maxlength="80" placeholder="自定义主体，如 ABCD1234（自动变 CLC-ABCD-1234）"><select id="licenseType"><option value="permanent">永久</option><option value="duration">激活后 N 天</option><option value="fixed">固定到期</option></select><input id="durationDays" type="number" value="7" min="1" max="36500"><input id="expiresAt" class="hidden" type="datetime-local"><input id="batchCount" type="number" value="1" min="1" max="15"><button id="createLicenseBtn" class="btn primary">生成授权</button></div><div style="height:7px"></div><input id="licenseNote" placeholder="备注（可选）"><div id="licenseStatus" class="status muted"></div></div><div class="panel glass list-panel"><div class="list-tools"><input id="licenseSearch" placeholder="搜索授权码"><select id="licenseStatusFilter"><option value="">全部状态</option><option value="active">有效</option><option value="expired">无效（已到期）</option><option value="disabled">已禁用</option><option value="invalid">全部无效</option></select><select id="licenseBindingFilter" aria-label="设备绑定筛选"><option value="">全部绑定状态</option><option value="bound">已绑定</option><option value="unbound">未绑定</option></select><select id="licenseTypeFilter" aria-label="授权类型筛选"><option value="">全部类型</option><option value="permanent">永久</option><option value="duration">按天</option><option value="fixed">固定到期</option></select><button id="exportAllBtn" class="btn secondary">导出全部</button><button id="exportFilteredBtn" class="btn secondary">导出筛选结果</button><button id="licenseSearchBtn" class="btn primary">搜索</button><button id="licenseResetBtn" class="btn secondary">清除</button></div><div class="table-wrap"><table><thead><tr><th>授权码</th><th>状态</th><th>类型</th><th>首次激活</th><th>到期</th><th>设备</th><th>创建</th><th>操作</th></tr></thead><tbody id="licenseRows"></tbody></table></div><div class="pager"><button id="licensePrevBtn" class="btn secondary">上一页</button><span id="licensePageInfo" class="page-info">第 1/1 页</span><button id="licenseNextBtn" class="btn secondary">下一页</button></div></div></section>
<section id="devices" class="section"><div class="panel glass list-panel"><div class="list-tools"><input id="deviceSearch" placeholder="搜索授权码 / 设备名 / 设备码"><select id="deviceBindingFilter"><option value="">全部状态</option><option value="bound">已绑定</option><option value="unbound">已解绑</option></select><button id="deviceSearchBtn" class="btn primary">搜索</button><button id="deviceResetBtn" class="btn secondary">清除</button></div><div class="notice">管理员解绑后，该设备记录可直接删除；删除会同步清理对应数据库记录。</div><div class="table-wrap"><table><thead><tr><th>设备</th><th>授权码</th><th>Windows</th><th>App</th><th>最近在线</th><th>状态</th><th>操作</th></tr></thead><tbody id="deviceRows"></tbody></table></div><div class="pager"><button id="devicePrevBtn" class="btn secondary">上一页</button><span id="devicePageInfo" class="page-info">第 1/1 页</span><button id="deviceNextBtn" class="btn secondary">下一页</button></div></div></section>
<section id="logs" class="section"><div class="panel glass" style="overflow:auto"><table><thead><tr><th>时间</th><th>事件</th><th>IP</th><th>详情</th></tr></thead><tbody id="logRows"></tbody></table></div></section>
<section id="settings" class="section"><div class="panel glass"><h3>域名与 API</h3><p>当前访问：<code id="currentOrigin">-</code></p><p>Bootstrap：<code id="bootstrapUrl">-</code></p><p>主授权地址：<code id="canonicalUrl">-</code></p><div class="notice">先在 Cloudflare Pages 绑定 Custom Domain，然后在这里保存。保存时只需要再次输入管理员密码。</div><div class="row"><input id="newDomain" placeholder="license.example.com"><input id="confirmPassword" type="password" placeholder="管理员密码（二次确认）"></div><div style="height:12px"></div><button id="saveDomainBtn" class="btn primary">检测并保存</button> <button id="rollbackDomainBtn" class="btn danger">恢复 Bootstrap 地址</button><div id="settingsStatus" class="status muted"></div></div><div class="panel glass"><h3>生产客户端认证流程</h3><div class="notice">首次激活 1 次；之后本地验证服务器签名 Lease。正常情况下仅在 Lease 到期前每约 72 小时执行 <b>challenge + refresh</b> 两次请求。</div><div id="apiList"></div></div></section>
</main>
</div>
<script>
(function(){
'use strict';
var CSRF=${csrfLiteral};
var PAGE_SIZE=10,licensePage=1,licenseTotalPages=1,devicePage=1,deviceTotalPages=1;
function q(id){return document.getElementById(id)}
function esc(v){return String(v==null?'':v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;')}
function setStatus(id,text,type){var el=q(id);if(!el)return;el.className='status '+(type||'muted');el.textContent=text||''}
async function call(path,opt){opt=opt||{};var headers=Object.assign({},opt.headers||{});if(opt.body!=null&&!headers['content-type'])headers['content-type']='application/json';headers['x-csrf-token']=CSRF;opt.headers=headers;opt.cache='no-store';try{var r=await fetch(path,opt);var text=await r.text();var data={};if(text){try{data=JSON.parse(text)}catch(_){data={success:false,message:'服务器返回格式异常（HTTP '+r.status+'）'}}}if(!r.ok&&data.success!==false)data.success=false;if(!r.ok&&!data.message)data.message='请求失败（HTTP '+r.status+'）';return data}catch(e){return {success:false,message:'网络请求失败：'+(e&&e.message?e.message:'未知错误')}}}
function authFailed(r){if(r&&(r.code==='UNAUTHORIZED'||r.code==='CSRF_OR_AUTH_FAILED')){location.replace('/admin');return true}return false}
async function loadDashboard(){var r=await call('/admin/api/dashboard');if(authFailed(r))return;if(!r.success){setStatus('globalStatus',r.message||'仪表盘加载失败','error');return}q('sTotal').textContent=r.stats.total;q('sActive').textContent=r.stats.active;q('sDisabled').textContent=r.stats.disabled;q('sDevices').textContent=r.stats.devices;setStatus('globalStatus','')}
function licenseTypeChanged(){var t=q('licenseType').value;q('durationDays').classList.toggle('hidden',t!=='duration');q('expiresAt').classList.toggle('hidden',t!=='fixed')}
function licenseTypeText(x){if(x.license_type==='permanent')return '永久';if(x.license_type==='duration')return '激活后 '+esc(x.duration_days)+' 天';if(x.license_type==='fixed')return '固定到期';return esc(x.license_type)}
function expiryText(x){if(x.license_type==='permanent')return '永久授权';if(x.license_type==='duration'&&!x.activated_at)return '未激活（激活后 '+esc(x.duration_days)+' 天）';return esc(x.expires_at||'—')}
function licenseStatusText(x){return x==='active'?'有效':(x==='expired'?'无效（已到期）':(x==='disabled'?'已禁用':esc(x)))}
function formatCustomLicenseKey(raw){var v=String(raw||'').trim().toUpperCase();if(!v)return '';v=v.replace(/[^A-Z0-9]/g,'');if(v.indexOf('CLC')===0)v=v.slice(3);v=v.slice(0,60);if(!v)return '';var parts=[];for(var i=0;i<v.length;i+=4)parts.push(v.slice(i,i+4));return 'CLC-'+parts.join('-')}
function updateLicensePager(p){p=p||{};licensePage=Number(p.page||1);licenseTotalPages=Number(p.totalPages||1);q('licensePageInfo').textContent='第 '+licensePage+'/'+licenseTotalPages+' 页，共 '+Number(p.total||0)+' 条';q('licensePrevBtn').disabled=licensePage<=1;q('licenseNextBtn').disabled=licensePage>=licenseTotalPages}
function updateDevicePager(p){p=p||{};devicePage=Number(p.page||1);deviceTotalPages=Number(p.totalPages||1);q('devicePageInfo').textContent='第 '+devicePage+'/'+deviceTotalPages+' 页，共 '+Number(p.total||0)+' 条';q('devicePrevBtn').disabled=devicePage<=1;q('deviceNextBtn').disabled=devicePage>=deviceTotalPages}
async function loadLicenses(reset){if(reset)licensePage=1;setStatus('licenseStatus','正在加载…');var path='/admin/api/licenses?page='+licensePage+'&pageSize='+PAGE_SIZE+'&q='+encodeURIComponent(q('licenseSearch').value.trim())+'&status='+encodeURIComponent(q('licenseStatusFilter').value)+'&binding='+encodeURIComponent(q('licenseBindingFilter').value)+'&type='+encodeURIComponent(q('licenseTypeFilter').value);var r=await call(path);if(authFailed(r))return;if(!r.success){setStatus('licenseStatus',r.message||'授权列表加载失败','error');return}var rows=(r.licenses||[]).map(function(x){var actions='';if(x.status==='active'){var renew='';if(x.license_type==='duration'&&x.activated_at){renew='<button class="btn success" data-action="renew" data-id="'+esc(x.id)+'" data-days="'+esc(x.duration_days||7)+'">续期</button>'}actions=renew+'<button class="btn secondary" data-action="toggle" data-id="'+esc(x.id)+'" data-op="disable">禁用</button>'}else{actions='<details class="more-wrap"><summary class="btn secondary more-btn" aria-label="更多操作">•••</summary><div class="more-menu"><button class="restore-item" data-action="toggle" data-id="'+esc(x.id)+'" data-op="enable">恢复</button><button class="danger-item" data-action="delete-license" data-id="'+esc(x.id)+'" data-key="'+esc(x.license_key)+'">删除</button></div></details>'}return '<tr><td><div class="copy-key"><code>'+esc(x.license_key)+'</code><button class="btn secondary copy-btn" data-action="copy" data-key="'+esc(x.license_key)+'" aria-label="复制授权码">复制</button></div></td><td><span class="pill '+esc(x.effective_status||x.status)+'">'+licenseStatusText(x.effective_status||x.status)+'</span></td><td>'+licenseTypeText(x)+'</td><td>'+esc(x.activated_at||'未激活')+'</td><td>'+expiryText(x)+'</td><td>'+(x.device_count?'<span class="pill">已绑定</span>':'未绑定')+'</td><td>'+esc((x.created_at||'').slice(0,10))+'</td><td><div class="actions">'+actions+'</div></td></tr>'}).join('');q('licenseRows').innerHTML=rows||'<tr><td colspan="8" class="muted">没有匹配的授权记录</td></tr>';labelCells('licenseRows',['授权码','状态','类型','首次激活','到期','设备','创建','操作']);updateLicensePager(r.pagination);setStatus('licenseStatus','当前筛选共 '+Number((r.pagination||{}).total||0)+' 条授权','muted')}
async function createLicense(){var fixed=q('expiresAt').value;var rawCustom=q('customKey').value;var formattedCustom=formatCustomLicenseKey(rawCustom);if(rawCustom.trim())q('customKey').value=formattedCustom;var body={licenseKey:formattedCustom,licenseType:q('licenseType').value,durationDays:Number(q('durationDays').value),expiresAt:fixed?new Date(fixed).toISOString():null,count:Number(q('batchCount').value),note:q('licenseNote').value};setStatus('licenseStatus','正在生成授权…');var r=await call('/admin/api/licenses',{method:'POST',body:JSON.stringify(body)});if(authFailed(r))return;if(!r.success){setStatus('licenseStatus',r.message||r.code||'生成失败','error');return}var nl=String.fromCharCode(10);alert('已生成 '+r.licenseKeys.length+' 个授权码'+nl+r.licenseKeys.join(nl));setStatus('licenseStatus','授权生成成功','ok');licensePage=1;await loadLicenses();await loadDashboard()}
async function renewLicense(id,defaultDays){var raw=prompt('续期多少天？续期会在当前到期时间之后追加；如果已经过期，则从现在开始追加。',String(defaultDays||7));if(raw===null)return;var days=Number(raw);if(!Number.isInteger(days)||days<1||days>36500){alert('请输入 1-36500 的整数天数');return}var r=await call('/admin/api/licenses/'+encodeURIComponent(id)+'/renew',{method:'POST',body:JSON.stringify({days:days})});if(authFailed(r))return;alert(r.success?'续期成功，新到期时间：'+r.expiresAt:(r.message||r.code||'续期失败'));if(r.success){await loadLicenses();await loadDashboard()}}
async function toggleLicense(id,op){var r=await call('/admin/api/licenses/'+encodeURIComponent(id)+'/'+op,{method:'POST',body:'{}'});if(authFailed(r))return;if(!r.success){alert(r.message||'操作失败');return}await loadLicenses();await loadDashboard()}\nasync function deleteLicense(id,key){if(!confirm('确认永久删除授权 '+key+' 吗？这会同时删除该授权关联的设备、challenge、关联日志和授权锁，删除后无法恢复。'))return;var r=await call('/admin/api/licenses/'+encodeURIComponent(id),{method:'DELETE'});if(authFailed(r))return;if(!r.success){alert(r.message||r.code||'删除失败');return}setStatus('licenseStatus','授权已从数据库永久删除','ok');await loadLicenses();await loadDevices();await loadDashboard()}
async function loadDevices(reset){if(reset)devicePage=1;var path='/admin/api/devices?page='+devicePage+'&pageSize='+PAGE_SIZE+'&q='+encodeURIComponent(q('deviceSearch').value.trim())+'&binding='+encodeURIComponent(q('deviceBindingFilter').value);var r=await call(path);if(authFailed(r))return;if(!r.success){setStatus('globalStatus',r.message||'设备列表加载失败','error');return}q('deviceRows').innerHTML=(r.devices||[]).map(function(x){var action=x.revoked_at?'<button class="btn danger" data-action="delete-device" data-id="'+esc(x.id)+'" data-name="'+esc(x.device_name||x.device_id)+'">删除</button>':'<button class="btn danger" data-action="revoke" data-id="'+esc(x.id)+'">解绑</button>';return '<tr><td>'+esc(x.device_name||x.device_id)+'</td><td><code>'+esc(x.license_key)+'</code></td><td>'+esc(x.windows_version)+'</td><td>'+esc(x.app_version)+'</td><td>'+esc(x.last_seen_at)+'</td><td>'+(x.revoked_at?'已解绑':'已绑定')+'</td><td>'+action+'</td></tr>'}).join('')||'<tr><td colspan="7" class="muted">没有匹配的设备记录</td></tr>';labelCells('deviceRows',['设备','授权码','Windows','App','最近在线','状态','操作']);updateDevicePager(r.pagination)}
async function revokeDevice(id){if(!confirm('确认解绑此设备？解绑后，该授权码可绑定另一台设备；该设备也可以绑定其他授权码。'))return;var r=await call('/admin/api/devices/'+encodeURIComponent(id)+'/revoke',{method:'POST',body:'{}'});if(authFailed(r))return;if(!r.success){alert(r.message||'解绑失败');return}await loadDevices();await loadLicenses();await loadDashboard()}\nasync function deleteDevice(id,name){if(!confirm('确认永久删除已解绑设备 '+name+' 的数据库记录吗？删除后无法恢复。'))return;var r=await call('/admin/api/devices/'+encodeURIComponent(id),{method:'DELETE'});if(authFailed(r))return;if(!r.success){alert(r.message||r.code||'删除失败');return}await loadDevices();await loadLicenses();await loadDashboard()}
async function loadLogs(){var r=await call('/admin/api/logs');if(authFailed(r))return;if(!r.success){setStatus('globalStatus',r.message||'日志加载失败','error');return}q('logRows').innerHTML=(r.logs||[]).map(function(x){return '<tr><td>'+esc(x.created_at)+'</td><td>'+esc(x.event_type)+'</td><td>'+esc(x.ip)+'</td><td><code>'+esc(x.detail)+'</code></td></tr>'}).join('')}
async function loadSettings(){var r=await call('/admin/api/settings');if(authFailed(r))return;if(!r.success){setStatus('settingsStatus',r.message||'设置加载失败','error');return}q('currentOrigin').textContent=r.currentOrigin;q('canonicalUrl').textContent=r.canonicalBaseUrl;q('bootstrapUrl').textContent=r.bootstrapBaseUrl+'/bootstrap/v1/config';var eps=['/api/v1/license/activate','/api/v1/device/challenge','/api/v1/license/refresh','/api/v1/health','/api/v1/meta'];q('apiList').innerHTML=eps.map(function(x){return '<p><code>'+esc(r.canonicalBaseUrl+x)+'</code></p>'}).join('');setStatus('settingsStatus','')}
async function saveDomain(){var body={baseUrl:q('newDomain').value,password:q('confirmPassword').value};setStatus('settingsStatus','正在检测域名…');var r=await call('/admin/api/settings/domain',{method:'POST',body:JSON.stringify(body)});if(authFailed(r))return;setStatus('settingsStatus',r.success?'主授权域名已更新':(r.message||r.code||'保存失败'),r.success?'ok':'error');if(r.success)await loadSettings()}
async function rollbackDomain(){if(!confirm('确认恢复为 Bootstrap 地址？'))return;var r=await call('/admin/api/settings/domain/rollback',{method:'POST',body:JSON.stringify({password:q('confirmPassword').value})});if(authFailed(r))return;setStatus('settingsStatus',r.success?'已恢复 Bootstrap 地址':(r.message||'验证失败'),r.success?'ok':'error');if(r.success)await loadSettings()}
async function logout(){var r=await call('/admin/api/logout',{method:'POST',body:'{}'});if(r.success)location.replace('/admin');else alert(r.message||'退出失败')}
function showTab(name,label){document.querySelectorAll('.nav-btn').forEach(function(b){b.classList.toggle('active',b.getAttribute('data-tab')===name)});document.querySelectorAll('.section').forEach(function(s){s.classList.remove('active')});var section=q(name);if(section)section.classList.add('active');q('title').textContent=label||name;if(name==='dashboard')loadDashboard();if(name==='licenses')loadLicenses();if(name==='devices')loadDevices();if(name==='logs')loadLogs();if(name==='settings')loadSettings()}
document.querySelectorAll('.nav-btn').forEach(function(btn){btn.addEventListener('click',function(){showTab(btn.getAttribute('data-tab')||'dashboard',btn.textContent||'')})});
q('licenseType').addEventListener('change',licenseTypeChanged);
q('licenseSearchBtn').addEventListener('click',function(){loadLicenses(true)});
q('licenseResetBtn').addEventListener('click',function(){q('licenseSearch').value='';q('licenseStatusFilter').value='';q('licenseBindingFilter').value='';q('licenseTypeFilter').value='';loadLicenses(true)});
q('licenseStatusFilter').addEventListener('change',function(){loadLicenses(true)});
q('licenseSearch').addEventListener('keydown',function(e){if(e.key==='Enter')loadLicenses(true)});
q('licensePrevBtn').addEventListener('click',function(){if(licensePage>1){licensePage--;loadLicenses()}});
q('licenseNextBtn').addEventListener('click',function(){if(licensePage<licenseTotalPages){licensePage++;loadLicenses()}});
q('deviceSearchBtn').addEventListener('click',function(){loadDevices(true)});
q('deviceResetBtn').addEventListener('click',function(){q('deviceSearch').value='';q('deviceBindingFilter').value='';loadDevices(true)});
q('deviceBindingFilter').addEventListener('change',function(){loadDevices(true)});
q('deviceSearch').addEventListener('keydown',function(e){if(e.key==='Enter')loadDevices(true)});
q('devicePrevBtn').addEventListener('click',function(){if(devicePage>1){devicePage--;loadDevices()}});
q('deviceNextBtn').addEventListener('click',function(){if(devicePage<deviceTotalPages){devicePage++;loadDevices()}});
q('createLicenseBtn').addEventListener('click',createLicense);
q('logoutBtn').addEventListener('click',logout);
q('saveDomainBtn').addEventListener('click',saveDomain);
q('rollbackDomainBtn').addEventListener('click',rollbackDomain);
q('licenseRows').addEventListener('click',function(e){var target=e.target;if(!(target instanceof Element))return;var btn=target.closest('button[data-action]');if(!btn)return;var action=btn.getAttribute('data-action');var id=btn.getAttribute('data-id')||'';if(action==='copy')copyKey(btn.getAttribute('data-key')||'',btn);if(action==='toggle')toggleLicense(id,btn.getAttribute('data-op')||'');if(action==='renew')renewLicense(id,Number(btn.getAttribute('data-days')||7));if(action==='delete-license')deleteLicense(id,btn.getAttribute('data-key')||'')});
q('deviceRows').addEventListener('click',function(e){var target=e.target;if(!(target instanceof Element))return;var btn=target.closest('button[data-action]');if(!btn)return;var action=btn.getAttribute('data-action');var id=btn.getAttribute('data-id')||'';if(action==='revoke')revokeDevice(id);if(action==='delete-device')deleteDevice(id,btn.getAttribute('data-name')||'')});

function labelCells(id,labels){q(id).querySelectorAll('tr').forEach(function(row){Array.from(row.children).forEach(function(td,i){td.setAttribute('data-label',labels[i]||'')})})}
async function copyKey(key,button){try{await navigator.clipboard.writeText(key);var old=button.textContent;button.textContent='已复制';setTimeout(function(){button.textContent=old},1600)}catch(_){setStatus('licenseStatus','复制失败，请选中授权码手动复制','error')}}
function csvCell(value){var s=String(value==null?'':value);if(/^[=+@\\t\\r-]/.test(s))s="'"+s;return '"'+s.replace(/"/g,'""')+'"'}
async function exportLicenses(filtered){var buttons=[q('exportAllBtn'),q('exportFilteredBtn')];buttons.forEach(function(b){b.disabled=true});try{var rows=[],page=1,totalPages=1;var filter=filtered?'&q='+encodeURIComponent(q('licenseSearch').value.trim())+'&status='+encodeURIComponent(q('licenseStatusFilter').value)+'&binding='+encodeURIComponent(q('licenseBindingFilter').value)+'&type='+encodeURIComponent(q('licenseTypeFilter').value):'';do{var r=await call('/admin/api/licenses?page='+page+'&pageSize=50'+filter);if(authFailed(r))return;if(!r.success)throw new Error(r.message||'导出失败');rows=rows.concat(r.licenses||[]);totalPages=Number(r.pagination.totalPages);setStatus('licenseStatus','正在导出 '+page+'/'+totalPages+' 页…');page++}while(page<=totalPages);var seen=new Set();rows=rows.filter(function(x){if(seen.has(x.id))return false;seen.add(x.id);return true});var lines=[['授权码','状态','设备绑定','类型','天数','首次激活','到期时间','创建时间','备注']];rows.forEach(function(x){lines.push([x.license_key,licenseStatusText(x.effective_status||x.status),x.device_count?'已绑定':'未绑定',x.license_type,x.duration_days,x.activated_at,x.expires_at,x.created_at,x.note])});var content=String.fromCharCode(65279)+lines.map(function(row){return row.map(csvCell).join(',')}).join(String.fromCharCode(13,10));var url=URL.createObjectURL(new Blob([content],{type:'text/csv;charset=utf-8'}));var a=document.createElement('a');a.href=url;a.download='CleanC-licenses-'+(filtered?'filtered-':'all-')+new Date().toISOString().slice(0,10)+'.csv';document.body.appendChild(a);a.click();a.remove();setTimeout(function(){URL.revokeObjectURL(url)},10000);setStatus('licenseStatus','已导出 '+rows.length+' 个授权码','ok')}catch(e){setStatus('licenseStatus',e.message||'导出失败','error')}finally{buttons.forEach(function(b){b.disabled=false})}}
q('exportAllBtn').addEventListener('click',function(){exportLicenses(false)});
q('exportFilteredBtn').addEventListener('click',function(){exportLicenses(true)});
['licenseBindingFilter','licenseTypeFilter'].forEach(function(id){q(id).addEventListener('change',function(){loadLicenses(true)})});
licenseTypeChanged();
loadDashboard();
})();
</script>
</body>
</html>`;
}

export async function prepareAuthenticatedAdminResponse(
  response: Response,
  request: Request,
  env: Env,
): Promise<Response> {
  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('text/html')) return response;
  const csrf = await csrfToken(request, env);
  return new Response(renderDashboard(csrf), {
    status: 200,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
      'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
      'permissions-policy': 'camera=(), microphone=(), geolocation=()',
    },
  });
}

