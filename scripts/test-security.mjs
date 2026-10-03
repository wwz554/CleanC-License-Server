import {DatabaseSync} from 'node:sqlite';
import {generateKeyPairSync,sign,verify} from 'node:crypto';
import assert from 'node:assert/strict';
import {build} from 'esbuild';
import {pathToFileURL} from 'node:url';
import {mkdtempSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
const dir=mkdtempSync(join(tmpdir(),'cleanc-security-'));
await build({entryPoints:['src/router-turnstile.ts'],outdir:dir,bundle:true,platform:'node',format:'esm'});
const {handleTurnstileAppRequest:handle}=await import(pathToFileURL(join(dir,'router-turnstile.js')));
const post=(path,body,ip=crypto.randomUUID())=>new Request('https://test'+path,{method:'POST',headers:{'content-type':'application/json','cf-connecting-ip':ip},body:typeof body==='string'?body:JSON.stringify(body)});
// Invalid outer bodies must fail before touching a database or invoking Turnstile.
const noDb={DB:{prepare(){throw Error('Invalid input reached DB');}}};
for(const path of ['/admin/api/login','/api/v1/device/challenge','/api/v1/license/refresh']){
 for(const body of ['null','[]','{'])assert.equal((await handle(post(path,body),noDb)).status,400);
 assert.equal((await handle(post(path,{junk:'x'.repeat(65536)}),noDb)).status,413);
}
let pulls=0,canceled=false;
const stream=new ReadableStream({pull(c){pulls++;c.enqueue(new Uint8Array(8192));if(pulls===40)c.close();},cancel(){canceled=true;}});
const streamed=new Request('https://test/api/v1/license/refresh',{method:'POST',headers:{'content-type':'application/json'},body:stream,duplex:'half'});
assert.equal((await handle(streamed,noDb)).status,413);assert.ok(canceled&&pulls<40);
console.log('PASS outer route rejects malformed and oversized streamed bodies before initialization');

const sql=new DatabaseSync(':memory:');
function prepare(query){let args=[];return{
 bind(...values){args=values;return this;},
 first(column){const row=sql.prepare(query).get(...args);return column?row?.[column]??null:row??null;},
 all(){return{results:sql.prepare(query).all(...args),success:true};},
 run(){const r=sql.prepare(query).run(...args);return{success:true,meta:{changes:Number(r.changes),last_row_id:Number(r.lastInsertRowid)}};}
};}
const server=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),device=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),other=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const env={DB:{prepare,batch(statements){sql.exec('BEGIN');try{const results=statements.map(s=>s.run());sql.exec('COMMIT');return results;}catch(e){sql.exec('ROLLBACK');throw e;}}},
 ADMIN_PASSWORD:'fixture-password-not-production',SESSION_SECRET:'fixture-session-secret-not-production',TURNSTILE_SECRET:'fixture',TURNSTILE_SITE_KEY:'fixture',
 LICENSE_SIGNING_PRIVATE_KEY:server.privateKey.export({type:'pkcs8',format:'pem'}),DEVICE_PROOF_SECRET:'fixture-proof-secret'};
const health=await handle(new Request('https://test/api/v1/health'),env);
assert.equal(health.status,200,await health.text());
function add(id,type='permanent',expires=null){const now=new Date().toISOString();sql.prepare('INSERT INTO licenses(id,license_key,edition,status,license_type,expires_at,created_at,updated_at) VALUES(?,?,?, ?,?,?,?,?)').run(id,'CLC-'+id,'pro','active',type,expires,now,now);}
add('FIXTURE');add('OTHER');
const pub=device.publicKey.export({type:'spki',format:'pem'}).toString();
const binding={licenseKey:'CLC-FIXTURE',deviceId:'CLEAN-TEST-DEVICE',devicePublicKey:pub};
const activated=await handle(post('/api/v1/license/activate',binding),env);
assert.equal(activated.status,200);const lease=await activated.json();
assert.ok(verify('sha256',Buffer.from(lease.signedPayload,'base64url'),{key:server.publicKey,dsaEncoding:'ieee-p1363'},Buffer.from(lease.signature,'base64url')));
const signed=JSON.parse(Buffer.from(lease.signedPayload,'base64url'));assert.equal(signed.deviceId,binding.deviceId);
assert.equal((await handle(post('/api/v1/license/activate',{...binding,deviceId:'PSCOPE-OTHER'}),env)).status,409);
assert.equal((await handle(post('/api/v1/license/activate',{...binding,licenseKey:'CLC-OTHER'}),env)).status,409);
const wrongKey=await handle(post('/api/v1/license/activate',{...binding,devicePublicKey:other.publicKey.export({type:'spki',format:'pem'}).toString()}),env);
assert.equal(wrongKey.status,403);assert.equal((await wrongKey.json()).code,'DEVICE_KEY_MISMATCH');
assert.equal(sql.prepare('SELECT count(*) n FROM devices WHERE revoked_at IS NULL').get().n,1);
console.log('PASS signed online lease, one license per CleanC or ProcessScope device, no silent key replacement');
// Legacy upgrade uses possession of the EXISTING device key, never a local grant.
const offlineChallenge=await handle(post('/api/v1/offline/challenge',{deviceId:binding.deviceId}),env);
assert.equal(offlineChallenge.status,200);const offlineNonce=(await offlineChallenge.json()).nonce;
assert.equal((await handle(post('/api/v1/offline/refresh',{deviceId:binding.deviceId,nonce:offlineNonce,signature:'invalid'}),env)).status,403);
const migrated=await handle(post('/api/v1/offline/refresh',{deviceId:binding.deviceId,nonce:offlineNonce,signature:sign('sha256',Buffer.from(offlineNonce),{key:device.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url')}),env);
assert.equal(migrated.status,200);const signedOffline=(await migrated.json()).offlineProof;
assert.ok(verify('sha256',Buffer.from(signedOffline.signedPayload,'base64url'),{key:server.publicKey,dsaEncoding:'ieee-p1363'},Buffer.from(signedOffline.signature,'base64url')));
const offlineGrant=JSON.parse(Buffer.from(signedOffline.signedPayload,'base64url'));
assert.equal(offlineGrant.purpose,'offline-entitlement-v1');assert.equal(offlineGrant.lease.isPermanent,true);
assert.equal(offlineGrant.lease.licenseExpiresAt,null);assert.equal(offlineGrant.lease.deviceId,binding.deviceId);
assert.equal(offlineGrant.lease.expiresAt,'9999-12-31T23:59:59.9999999+00:00');
assert.equal(offlineGrant.requestHash,'');assert.equal(offlineGrant.codeHash,'');
assert.equal(offlineGrant.challengeNonce,offlineNonce);
assert.equal((await handle(post('/api/v1/offline/challenge',{deviceId:'UNBOUND'}),env)).status,403);
console.log('PASS automatic offline migration requires device proof and returns signed full-term entitlement');
async function challenge(){const r=await handle(post('/api/v1/device/challenge',binding),env);assert.equal(r.status,200);return(await r.json()).nonce;}
function refreshBody(nonce,key=device.privateKey){return{licenseKey:binding.licenseKey,deviceId:binding.deviceId,nonce,signature:sign('sha256',Buffer.from(nonce),{key,dsaEncoding:'ieee-p1363'}).toString('base64url')};}
let nonce=await challenge();
assert.equal((await handle(post('/api/v1/license/refresh',refreshBody(nonce,other.privateKey)),env)).status,403);
assert.equal((await handle(post('/api/v1/license/refresh',refreshBody(nonce)),env)).status,200);
assert.ok([403,409].includes((await handle(post('/api/v1/license/refresh',refreshBody(nonce)),env)).status));
nonce=await challenge();
const concurrent=await Promise.all([handle(post('/api/v1/license/refresh',refreshBody(nonce)),env),handle(post('/api/v1/license/refresh',refreshBody(nonce)),env)]);
assert.equal(concurrent.filter(r=>r.status===200).length,1);
nonce=await challenge();sql.prepare('UPDATE device_challenges SET expires_at=? WHERE nonce=?').run('2020-01-01T00:00:00.000Z',nonce);
assert.equal((await handle(post('/api/v1/license/refresh',refreshBody(nonce)),env)).status,403);
nonce=await challenge();sql.prepare("UPDATE licenses SET status='disabled' WHERE id='FIXTURE'").run();
assert.equal((await handle(post('/api/v1/license/refresh',refreshBody(nonce)),env)).status,403);
sql.prepare("UPDATE licenses SET status='active' WHERE id='FIXTURE'").run();
nonce=await challenge();sql.prepare("UPDATE devices SET revoked_at=? WHERE device_id=?").run(new Date().toISOString(),binding.deviceId);
assert.equal((await handle(post('/api/v1/license/refresh',refreshBody(nonce)),env)).status,403);
console.log('PASS device proof, replay and concurrent nonce reuse rejected, expired nonce, disabled license and revoked device denied');
for(const path of ['/admin/api/licenses/FIXTURE/disable','/admin/api/devices/unknown/revoke','/admin/api/licenses']){
 const response=await handle(post(path,{licenseType:'permanent'}),env);
 assert.ok([401,403].includes(response.status),path+' '+response.status);
}
for(const path of ['/api/v1/device/verify','/api/v1/license/validate'])
 assert.equal((await handle(post(path,binding),env)).status,410);
assert.equal(sql.prepare("SELECT count(*) n FROM licenses").get().n,2);
console.log('PASS unauthorized admin mutations denied and legacy proof endpoints retired');
sql.close();
