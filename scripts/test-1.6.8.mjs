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
 const data=await result.json();assert.equal(data.licenseType,type);assert.equal(data.code.replaceAll('-','').length,16);const minutes=type==='permanent'?0:Math.floor((Date.parse(data.expiresAt)-Date.UTC(2020,0,1))/60000);const meta=type==='permanent'?0:((type==='duration'?1:2)*0x40000000+minutes)>>>0;const packed=Buffer.alloc(10);packed.writeUInt32BE(meta);createHmac('sha256',s.secret).update('CleanC/offline/v2\n'+s.r+'\n'+meta).digest().copy(packed,4,0,6);assert.equal(shortCode(packed),data.code.replaceAll('-',''));assert.deepEqual(await (await issue(s,'CLC-'+id.toUpperCase())).json(),data)}
assert.equal((await issue(session('DEVICE-expired'),'CLC-EXPIRED')).status,403);
assert.equal((await issue(session('DEVICE-disabled'),'CLC-DISABLED')).status,403);
assert.equal((await issue(session('DEVICE-other'),'CLC-PERMANENT')).status,409);
const states=sql.prepare(`SELECT id,${effectiveStatusSql('licenses')} state FROM licenses`).all();assert.equal(states.find(x=>x.id==='expired').state,'expired');assert.equal(states.find(x=>x.id==='one-day').state,'active');
const unauthorized=await handleAdminPaginatedList(new Request('https://test/admin/api/licenses'),env);assert.equal(unauthorized.status,401);
const payload=Buffer.from(JSON.stringify({exp:Date.now()+60000})).toString('base64url');const sig=createHmac('sha256',env.SESSION_SECRET).update(payload).digest('base64url');
const list=await handleAdminPaginatedList(new Request('https://test/admin/api/licenses?status=expired',{headers:{cookie:'cleanc_session='+payload+'.'+sig}}),env);assert.equal((await list.json()).licenses.length,1);
for(const m of offlinePage.matchAll(/<script>([\s\S]*?)<\/script>/g))new Function(m[1]);
console.log('PASS: offline permanent, 1-day duration, fixed expiry, MAC, idempotent retry, expired/disabled, device binding, filters, unauthorized access, mobile JS');
// Configuration, malformed input, bounded chunked bodies and interrupted responses.
const endpoint='https://test/api/v1/offline/issue';
const req=(body)=>new Request(endpoint,{method:'POST',headers:{'content-type':'application/json','cf-connecting-ip':crypto.randomUUID()},body});
assert.equal((await handleOffline(req('{}'),{...env,OFFLINE_RSA_PRIVATE_KEY:''})).status,503);
const invalid=await handleOffline(req('{}'),{...env,OFFLINE_RSA_PRIVATE_KEY:'bad key'});
assert.equal(invalid.status,503);assert.equal((await invalid.json()).code,'OFFLINE_KEY_INVALID');
const ready=await handleOffline(new Request('https://test/api/v1/offline/readiness'),{...env,OFFLINE_RSA_PRIVATE_KEY:env.OFFLINE_RSA_PRIVATE_KEY.replaceAll('\n','\\n')});assert.equal(ready.status,200);
for(const body of ['null','[]','{'])assert.equal((await handleOffline(req(body),env)).status,400);
assert.equal((await handleOffline(req(JSON.stringify({request:'x'.repeat(13000)})),env)).status,413);
assert.equal((await handleOffline(req('{}'),{...env,DB:{prepare(){throw Error('db unavailable')}}})).status,503);
const {readJsonObject}=await (async()=>{await build({entryPoints:['src/request-json.ts'],outdir:dir,bundle:true,platform:'node',format:'esm'});return import(pathToFileURL(dir+'/request-json.js'));})();
let chunks=0;
const stream=new ReadableStream({pull(controller){chunks++;controller.enqueue(new Uint8Array(4096));if(chunks===20)controller.close();}});
await assert.rejects(()=>readJsonObject(new Request(endpoint,{method:'POST',headers:{'content-type':'application/json'},body:stream,duplex:'half'})),error=>error.status===413);
assert.ok(chunks<20,'Oversized body must be canceled before buffering the entire upload');
console.log('PASS: missing/invalid/escaped PEM, readiness, malformed JSON, byte limits, stream cancellation, DB outage');
sql.prepare('DELETE FROM rate_limits').run();
add('retry-after-db-error');const retrySession=session('DEVICE-retry-after-db-error');let failReceiptOnce=true;
const failingEnv={...env,DB:{...env.DB,async batch(statements){if(failReceiptOnce&&statements.length===4){failReceiptOnce=false;throw Error('simulated receipt persistence failure');}return env.DB.batch(statements);}}};
const retryRequest=()=>req(JSON.stringify({request:retrySession.r,licenseKey:'CLC-RETRY-AFTER-DB-ERROR'}));
assert.equal((await handleOffline(retryRequest(),failingEnv)).status,503);
assert.equal(sql.prepare('SELECT count(*) n FROM offline_activation_sessions WHERE session_id=?').get(retrySession.q.sessionId).n,0);
assert.equal((await handleOffline(retryRequest(),failingEnv)).status,200);
const tampered={...retrySession.q,deviceId:'DEVICE-tampered'};
assert.equal((await handleOffline(req(JSON.stringify({request:Buffer.from(JSON.stringify(tampered)).toString('base64url'),licenseKey:'CLC-RETRY-AFTER-DB-ERROR'})),env)).status,400);
console.log('PASS: failed receipt releases reservation, successful retry after device binding, OAEP context tampering rejected');
