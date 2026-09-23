import type { Env } from './worker';
import { handleProductionActivation } from './activation';
import { handleProductionRequest } from './production';
import { readJsonObject, RequestError, normalizePem } from './request-json';
const enc=new TextEncoder();
const alphabet='0123456789ABCDEFGHJKMNPQRSTVWXYZ';
export function shortCode(bytes:Uint8Array):string{
 let bits=0;
 let value=0n;
 let out='';
 for(const b of bytes.slice(0,10)){
  value=(value<<8n)|BigInt(b);bits+=8;
  while(bits>=5){bits-=5;out+=alphabet[Number((value>>BigInt(bits))&31n)];value=bits===0?0n:value&((1n<<BigInt(bits))-1n);}
 }
 return out;
}
function decode(s:string):Uint8Array<ArrayBuffer>{return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));}
function reply(data:unknown,status=200){return Response.json(data,{status,headers:{'cache-control':'no-store','referrer-policy':'no-referrer','x-content-type-options':'nosniff'}});}
export async function handleOffline(request:Request,env:Env):Promise<Response|null>{
 const path=new URL(request.url).pathname;
 if(path==='/offline/activate'&&request.method==='GET')return new Response(offlinePage,{headers:{'content-type':'text/html;charset=utf-8','cache-control':'no-store','referrer-policy':'no-referrer','content-security-policy':"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",'x-content-type-options':'nosniff'}});
 if((path==='/api/v1/offline/challenge'||path==='/api/v1/offline/refresh')&&request.method==='POST'){
  try{
   const body=await readJsonObject(request);if(typeof body.deviceId!=='string'||body.deviceId.length>200)return reply({success:false,code:'DEVICE_NOT_BOUND'},400);
   const row=await env.DB.prepare('SELECT l.license_key FROM devices d JOIN licenses l ON l.id=d.license_id WHERE d.device_id=? AND d.revoked_at IS NULL AND l.deleted_at IS NULL LIMIT 1').bind(body.deviceId).first<{license_key:string}>();
   if(!row)return reply({success:false,code:'DEVICE_NOT_BOUND',message:'设备已解绑'},403);
   const target=path.endsWith('/challenge')?'/api/v1/device/challenge':'/api/v1/license/refresh';
   const response=await handleProductionRequest(new Request(new URL(target,request.url),{method:'POST',headers:{'content-type':'application/json','cf-connecting-ip':request.headers.get('cf-connecting-ip')||'unknown'},body:JSON.stringify({...body,licenseKey:row.license_key})}),env);
   if(path.endsWith('/challenge')||!response.ok)return response;
   const payload=await response.json() as Record<string,unknown>;
   return reply({...payload,licenseKey:row.license_key},response.status);
  }catch(error){return error instanceof RequestError?reply({success:false,message:error.message},error.status):reply({success:false,code:'OFFLINE_UNAVAILABLE',message:'授权服务暂时不可用，请稍后重试。'},503);}
 }
 const readiness=path==='/api/v1/offline/readiness'&&request.method==='GET';
 if(!readiness&&(path!=='/api/v1/offline/issue'||request.method!=='POST'))return null;
 const secret=env.OFFLINE_RSA_PRIVATE_KEY;
 if(!secret)return reply({success:false,code:'OFFLINE_NOT_CONFIGURED',message:'离线激活尚未配置，请联系管理员设置离线密钥。'},503);
 let key:CryptoKey;
 try{key=await crypto.subtle.importKey('pkcs8',decode(normalizePem(secret).replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s/g,'')),{name:'RSA-OAEP',hash:'SHA-256'},false,['decrypt']);}
 catch{return reply({success:false,code:'OFFLINE_KEY_INVALID',message:'服务器离线密钥配置无效，请联系管理员。'},503);}
 if(readiness)return reply({success:true,legacyOfflineReady:true,protocol:'offline-v2',security:'client-shared-secret',message:'离线密钥格式有效；仍需核对客户端公钥配对并进行真实激活验收。'});
 if(!request.headers.get('content-type')?.includes('application/json'))return reply({success:false,message:'请求格式无效'},415);
 const ip=request.headers.get('cf-connecting-ip')||'unknown',now=Date.now(),window=Math.floor(now/60000);
 let clear:Uint8Array|undefined;let reservedSession:string|undefined;let validated=false;
 try{
 const limit=await env.DB.prepare(`INSERT INTO rate_limits(bucket_key,count,window_start) VALUES(?,1,?) ON CONFLICT(bucket_key) DO UPDATE SET count=CASE WHEN window_start<>? THEN 1 ELSE count+1 END,window_start=? RETURNING count`).bind('offline:'+ip,window,window,window).first<{count:number}>();
 if(!limit||limit.count>15)return reply({success:false,message:'请求过于频繁，请稍后重试。'},429);
  const body=await readJsonObject(request),r=String(body.request||''),licenseKey=String(body.licenseKey||'').trim().toUpperCase();
  if(r.length>8000||!licenseKey||licenseKey.length>200)throw Error('format');
  const q=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(decode(r)));
  if(!q||q.v!==2||q.app!=='CleanC'||!/^\w{32}$/.test(q.sessionId)||typeof q.deviceId!=='string'||q.deviceId.length>200||!q.deviceId||typeof q.devicePublicKey!=='string'||q.devicePublicKey.length>2000||!Number.isSafeInteger(q.createdAt)||q.createdAt>now+120000||now-q.createdAt>600000||typeof q.box!=='string'||q.box.length>600)throw Error('format');
  clear=new Uint8Array(await crypto.subtle.decrypt({name:'RSA-OAEP'},key,decode(q.box)));
  if(clear.length!==64)throw Error('box');
  // OAEP binds the one-time secret to the exact request context.
  const context=JSON.stringify([q.v,q.app,q.sessionId,q.deviceId,q.devicePublicKey,q.createdAt]);
  const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(context)));
  let mismatch=0;for(let i=0;i<32;i++)mismatch|=clear[32+i]^digest[i];if(mismatch)throw Error('context');
  validated=true;
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS offline_activation_sessions(session_id TEXT PRIMARY KEY,request_hash TEXT NOT NULL,license_hash TEXT NOT NULL,status TEXT NOT NULL,expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL)`).run();
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS offline_activation_receipts(session_id TEXT PRIMARY KEY,response_json TEXT NOT NULL,expires_at INTEGER NOT NULL)').run();
  const hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(r)))).map(x=>x.toString(16).padStart(2,'0')).join('');
  const licenseHash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(licenseKey)))).map(x=>x.toString(16).padStart(2,'0')).join('');
  const reserved=await env.DB.prepare(`INSERT INTO offline_activation_sessions VALUES(?,?,?,'pending',?,?) ON CONFLICT(session_id) DO NOTHING RETURNING session_id`).bind(q.sessionId,hash,licenseHash,now+600000,now).first();
  if(!reserved){
   const existing=await env.DB.prepare('SELECT request_hash,license_hash,status,expires_at FROM offline_activation_sessions WHERE session_id=?').bind(q.sessionId).first<{request_hash:string;license_hash:string;status:string;expires_at:number}>();
   if(existing?.request_hash===hash&&existing.license_hash===licenseHash&&existing.expires_at>now&&existing.status==='issued'){
    const receipt=await env.DB.prepare('SELECT response_json FROM offline_activation_receipts WHERE session_id=? AND expires_at>?').bind(q.sessionId,now).first<{response_json:string}>();
    if(receipt)return reply(JSON.parse(receipt.response_json));
   }
   return reply({success:false,code:'OFFLINE_SESSION_BUSY',message:'此二维码正在处理或已用于其他授权。可稍后重试；仍未成功请在电脑重新生成二维码。'},409);
  }
  reservedSession=q.sessionId;

  const activation=new Request(new URL('/api/v1/license/activate',request.url),{method:'POST',headers:{'content-type':'application/json','cf-connecting-ip':ip},body:JSON.stringify({licenseKey,deviceId:q.deviceId,devicePublicKey:q.devicePublicKey,deviceName:'Windows PC (offline)',appVersion:'1.6.8'})});
  const result=await handleProductionActivation(activation,env);
  if(!result.ok){await env.DB.prepare('DELETE FROM offline_activation_sessions WHERE session_id=? AND status=?').bind(q.sessionId,'pending').run();reservedSession=undefined;return result;}
  const hmac=await crypto.subtle.importKey('raw',clear.slice(0,32),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const accepted=await result.json() as {lease:{licenseType:string;licenseExpiresAt:string|null}};
  const type=accepted.lease.licenseType;
  const minutes=type==='permanent'?0:Math.floor((Date.parse(accepted.lease.licenseExpiresAt||'')-Date.UTC(2020,0,1))/60000);
  if(!Number.isSafeInteger(minutes)||minutes<0||minutes>0x3fffffff)throw Error('expiry');
  const meta=type==='permanent'?0:((type==='duration'?1:2)*0x40000000+minutes)>>>0;
  const tag=new Uint8Array(await crypto.subtle.sign('HMAC',hmac,enc.encode('CleanC/offline/v2\n'+r+'\n'+meta)));
  const packed=new Uint8Array(10);new DataView(packed.buffer).setUint32(0,meta);packed.set(tag.slice(0,6),4);
  const code=shortCode(packed);
  const receipt={success:true,code:code.match(/.{4}/g)!.join('-'),expiresAt:type==='permanent'?null:new Date(Date.UTC(2020,0,1)+minutes*60000).toISOString(),licenseType:type};
  await env.DB.batch([
   env.DB.prepare('INSERT INTO offline_activation_receipts VALUES(?,?,?)').bind(q.sessionId,JSON.stringify(receipt),q.createdAt+600000),
   env.DB.prepare("UPDATE offline_activation_sessions SET status='issued' WHERE session_id=?").bind(q.sessionId),
   env.DB.prepare('DELETE FROM offline_activation_sessions WHERE expires_at<?').bind(now-86400000),
   env.DB.prepare('DELETE FROM offline_activation_receipts WHERE expires_at<?').bind(now)
  ]);
  reservedSession=undefined;return reply(receipt);
 }catch(error){
  if(reservedSession){try{await env.DB.prepare("DELETE FROM offline_activation_sessions WHERE session_id=? AND status='pending'").bind(reservedSession).run();}catch{/* A failed DB is reported as unavailable, never as bad user input. */}}
  if(error instanceof RequestError)return reply({success:false,message:error.message},error.status);
  if(validated||!(error instanceof SyntaxError||error instanceof DOMException||error instanceof Error&&['format','box','context'].includes(error.message)))return reply({success:false,code:'OFFLINE_UNAVAILABLE',message:'授权服务暂时不可用，请稍后重试同一个二维码。'},503);
  return reply({success:false,code:'OFFLINE_REQUEST_INVALID',message:'二维码无效、已超时或与服务器密钥不匹配，请重新生成；仍失败请联系管理员。'},400);
 }finally{clear?.fill(0);}
}
export const offlinePage=`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CleanC 离线激活</title><style>*{box-sizing:border-box}body{margin:0;min-height:100svh;display:grid;place-items:center;padding:24px;font:16px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#173052;background:radial-gradient(at 0 0,#d2ecff,transparent 60%),radial-gradient(at 100% 80%,#e8dfff,transparent 60%),#f4f8ff}main{width:100%;max-width:460px;padding:32px;background:#ffffffbe;backdrop-filter:blur(30px);border:1px solid white;border-radius:30px;box-shadow:0 24px 80px #294b7520}input,button{width:100%;font:inherit;padding:16px;border-radius:15px;margin:8px 0;border:1px solid #d4deed}button{background:#2673e6;color:white;cursor:pointer;min-height:48px}button:disabled{opacity:.5}p{line-height:1.7;color:#62728a}output{display:block;font-size:24px;font-weight:700;overflow-wrap:anywhere;margin:20px 0}input:focus-visible,button:focus-visible{outline:3px solid #438cff;outline-offset:3px}</style><main><small>CLEANC · LICENSE</small><h1>离线激活</h1><p>输入授权码，获取当前电脑专用的 16 位激活码。与在线激活采用相同授权类型和到期时间。</p><form id="form"><label for="key">授权码</label><input id="key" autocomplete="off" maxlength="200" placeholder="CLC-XXXX-XXXX-XXXX-XXXX" required><button id="submit">确认授权</button></form><output id="result" aria-live="polite"></output><p id="message">无需登录管理后台。二维码十分钟内有效。</p></main><script>
const form=document.getElementById('form'),b=document.getElementById('submit'),m=document.getElementById('message');
const supplied=location.hash.slice(1);let r=supplied;
try{
 if(supplied)sessionStorage.setItem('cleanc-offline-request',JSON.stringify({r:supplied,at:Date.now()}));
 else{const saved=JSON.parse(sessionStorage.getItem('cleanc-offline-request')||'null');if(saved&&Date.now()-saved.at<600000)r=saved.r;}
}catch{}
history.replaceState(null,'',location.pathname);
if(!r){b.disabled=true;m.textContent='缺少有效的扫码请求。请回到电脑重新生成并扫描二维码。';}
async function readResponse(response){let data;try{data=await response.json();}catch{throw Error('服务暂时未返回有效结果，请稍后重试。');}if(!response.ok||!data.success)throw Error(data.message||'激活失败，请稍后重试。');return data;}
form.addEventListener('submit',async e=>{
 e.preventDefault();if(!r)return;b.disabled=true;m.textContent='正在核验授权，请稍候…';
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),25000);
 try{
  const data=await readResponse(await fetch('/api/v1/offline/issue',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({request:r,licenseKey:document.getElementById('key').value}),cache:'no-store',signal:controller.signal}));
  document.getElementById('result').textContent=data.code;document.getElementById('key').value='';
  m.textContent='请在电脑点击“我已扫码”，输入以上激活码。'+(data.expiresAt?'有效期至 '+new Date(data.expiresAt).toLocaleString():'永久授权');form.hidden=true;
 }catch(err){m.textContent=err.name==='AbortError'?'网络响应超时，可以直接重试；不要立即更换二维码。':err.message;}
 finally{clearTimeout(timer);b.disabled=false;}
});
</script></html>`;
