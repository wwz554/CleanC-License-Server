import fs from 'node:fs';
import path from 'node:path';
import { createPrivateKey, createPublicKey } from 'node:crypto';

const root=path.resolve(import.meta.dirname,'..');
const folder=path.resolve(process.argv[2]||path.join(root,'private-secrets'));
const secrets=JSON.parse(fs.readFileSync(path.join(folder,'cloudflare-secrets.json'),'utf8'));
for(const name of ['ADMIN_PASSWORD','SESSION_SECRET','TURNSTILE_SECRET','LICENSE_SIGNING_PRIVATE_KEY','OFFLINE_RSA_PRIVATE_KEY']) {
  if(typeof secrets[name]!=='string'||!secrets[name].trim())throw new Error('MISSING_BACKUP_'+name);
}
const der=key=>createPublicKey(key).export({type:'spki',format:'der'});
const signing=createPrivateKey(secrets.LICENSE_SIGNING_PRIVATE_KEY.replace(/\\n/g,'\n'));
const offline=createPrivateKey(secrets.OFFLINE_RSA_PRIVATE_KEY.replace(/\\n/g,'\n'));
if(signing.asymmetricKeyType!=='ec'||signing.asymmetricKeyDetails.namedCurve!=='prime256v1')throw new Error('WRONG_SIGNING_KEY_TYPE');
if(offline.asymmetricKeyType!=='rsa')throw new Error('WRONG_OFFLINE_KEY_TYPE');
if(!der(signing).equals(der(fs.readFileSync(path.join(root,'server-public.pem')))))throw new Error('SIGNING_KEY_DIFFERS_FROM_CLIENTS');
if(!der(offline).equals(der(fs.readFileSync(path.join(root,'offline-public.pem')))))throw new Error('OFFLINE_KEY_DIFFERS_FROM_BACKUP');
console.log('Original P-256 and RSA key pairs match the recovery public keys. Secret values were not printed.');
