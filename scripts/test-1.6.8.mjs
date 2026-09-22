import {DatabaseSync} from 'node:sqlite';
import {generateKeyPairSync,publicEncrypt,createHash,createHmac,constants} from 'node:crypto';
import assert from 'node:assert/strict';
import {build} from 'esbuild';
import {pathToFileURL} from 'node:url';
import {mkdtempSync} from 'node:fs';
import {tmpdir} from 'node:os';
const dir=mkdtempSync(tmpdir()+'/cleanc-test-');
await build({entryPoints:['src/offline-activation.ts','src/admin-list.ts','src/license-status.ts'],outdir:dir,bundle:true,platform:'node',format:'esm'});
const {handleOffline,shortCode,offlinePage}=await import(pathToFileURL(dir+'/offline-activation.js'));
const {effectiveStatusSql}=await import(pathToFileURL(dir+'/license-status.js'));
const {handleAdminPaginatedList}=await import(pathToFileURL(dir+'/admin-list.js'));
const sql=new DatabaseSync(':memory:');
sql.exec(`CREATE TABLE licenses(id TEXT PRIMARY KEY,license_key TEXT,edition TEXT,status TEXT,license_type TEXT,duration_days INTEGER,expires_at TEXT,activated_at TEXT,created_at TEXT,updated_at TEXT,deleted_at TEXT);CREATE TABLE devices(id TEXT,license_id TEXT,device_id TEXT,public_key TEXT,device_name TEXT,windows_version TEXT,app_version TEXT,first_seen_at TEXT,last_seen_at TEXT,revoked_at TEXT);CREATE UNIQUE INDEX one_device ON devices(device_id) WHERE revoked_at IS NULL;CREATE UNIQUE INDEX one_license ON devices(license_id) WHERE revoked_at IS NULL;CREATE TABLE rate_limits(bucket_key TEXT PRIMARY KEY,count INTEGER,window_start INTEGER);CREATE TABLE activation_locks(license_key TEXT PRIMARY KEY,lock_token TEXT,locked_until INTEGER);CREATE TABLE audit_logs(id TEXT,event_type TEXT,ip TEXT,license_id TEXT,device_id TEXT,detail TEXT,created_at TEXT);CREATE TABLE system_settings(setting_key TEXT,setting_value TEXT);`);
function prepare(q){let values=[];return {bind(...args){values=args;return this},async first(){return sql.prepare(q).get(...values)||null},async all(){return {results:sql.prepare(q).all(...values)}},async run(){return sql.prepare(q).run(...values)}}}
const rsa=generateKeyPairSync('rsa',{modulusLength:3072});const ec=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const env={DB:{prepare,async batch(statements){sql.exec('BEGIN');try{for(const x of statements)await x.run();sql.exec('COMMIT')}catch(e){sql.exec('ROLLBACK');throw e}}},OFFLINE_RSA_PRIVATE_KEY:rsa.privateKey.export({type:'pkcs8',format:'pem'}),LICENSE_SIGNING_PRIVATE_KEY:ec.privateKey.export({type:'pkcs8',format:'pem'}),SESSION_SECRET:'test-only-secret'};
function add(id,type='permanent',days=null,expiry=null,status='active'){sql.prepare('INSERT INTO licenses VALUES(?,?,?,?,?,?,?,NULL,?,NULL,NULL)').run(id,'CLC-'+id.toUpperCase(),'standard',status,type,days,expiry,new Date().toISOString())}
add('permanent');add('one-day','duration',1);add('fixed','fixed',null,new Date(Date.now()+86400000).toISOString());add('expired','fixed',null,new Date(Date.now()-1000).toISOString());add('disabled','permanent',null,null,'disabled');
function session(deviceId){const secret=crypto.getRandomValues(new Uint8Array(32));const q={v:2,app:'CleanC',sessionId:crypto.randomUUID().replaceAll('-',''),deviceId,devicePublicKey:ec.publicKey.export({type:'spki',format:'pem'}).toString(),createdAt:Date.now()-1000};const digest=createHash('sha256').update(JSON.stringify([q.v,q.app,q.sessionId,q.deviceId,q.devicePublicKey,q.createdAt])).digest();q.box=publicEncrypt({key:rsa.publicKey,oaepHash:'sha256',padding:constants.RSA_PKCS1_OAEP_PADDING},Buffer.concat([secret,digest])).toString('base64url');const r=Buffer.from(JSON.stringify(q)).toString('base64url');return {q,r,secret}}
async function issue(s,key){return handleOffline(new Request('https://test/offline'.replace('/offline','/api/v1/offline/issue'),{method:'POST',headers:{'content-type':'application/json','cf-connecting-ip':'test'},body:JSON.stringify({request:s.r,licenseKey:key})}),env)}
for(const [id,type] of [['permanent','permanent'],['one-day','duration'],['fixed','fixed']]){const s=session('DEVICE-'+id);const result=await issue(s,'CLC-'+id.toUpperCase()); // keys are case insensitive at boundary; fixtures match production uppercase
 if(result.status!==200){const data=await result.json();throw Error(JSON.stringify(data))}
 const data=await result.json();assert.equal(data.licenseType,type);assert.equal(data.code.replaceAll('-','').length,16);const minutes=type==='permanent'?0:Math.floor((Date.parse(data.expiresAt)-Date.UTC(2020,0,1))/60000);const meta=type==='permanent'?0:((type==='duration'?1:2)*0x40000000+minutes)>>>0;const packed=Buffer.alloc(10);packed.writeUInt32BE(meta);createHmac('sha256',s.secret).update('CleanC/offline/v2\n'+s.r+'\n'+meta).digest().copy(packed,4,0,6);assert.equal(shortCode(packed),data.code.replaceAll('-',''));assert.equal((await issue(s,'CLC-'+id.toUpperCase())).status,409)}
assert.equal((await issue(session('DEVICE-expired'),'CLC-EXPIRED')).status,403);
assert.equal((await issue(session('DEVICE-disabled'),'CLC-DISABLED')).status,403);
assert.equal((await issue(session('DEVICE-other'),'CLC-PERMANENT')).status,409);
const states=sql.prepare(`SELECT id,${effectiveStatusSql('licenses')} state FROM licenses`).all();assert.equal(states.find(x=>x.id==='expired').state,'expired');assert.equal(states.find(x=>x.id==='one-day').state,'active');
const unauthorized=await handleAdminPaginatedList(new Request('https://test/admin/api/licenses'),env);assert.equal(unauthorized.status,401);
const payload=Buffer.from(JSON.stringify({exp:Date.now()+60000})).toString('base64url');const sig=createHmac('sha256',env.SESSION_SECRET).update(payload).digest('base64url');
const list=await handleAdminPaginatedList(new Request('https://test/admin/api/licenses?status=expired',{headers:{cookie:'cleanc_session='+payload+'.'+sig}}),env);assert.equal((await list.json()).licenses.length,1);
for(const m of offlinePage.matchAll(/<script>([\s\S]*?)<\/script>/g))new Function(m[1]);
console.log('PASS: offline permanent, 1-day duration, fixed expiry, MAC, replay, expired/disabled, device binding, filters, unauthorized access, mobile JS');
