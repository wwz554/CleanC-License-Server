import {readFileSync} from 'node:fs';
import {createPrivateKey,createPublicKey,createHash,timingSafeEqual} from 'node:crypto';
const [privatePath,clientPublicPath]=process.argv.slice(2);
if(!privatePath||!clientPublicPath){console.error('Usage: node scripts/check-offline-key.mjs <private.pem> <client offline-public.pem>');process.exit(2);}
try{
 const pem=readFileSync(privatePath,'utf8').replaceAll('\\r\\n','\n').replaceAll('\\n','\n');
 const privateKey=createPrivateKey(pem),publicKey=createPublicKey(privateKey);
 if(privateKey.asymmetricKeyType!=='rsa'||privateKey.asymmetricKeyDetails.modulusLength!==3072)throw Error('Expected the RSA-3072 key used by the v2 client');
 const actual=publicKey.export({type:'spki',format:'der'}),expected=createPublicKey(readFileSync(clientPublicPath)).export({type:'spki',format:'der'});
 if(actual.length!==expected.length||!timingSafeEqual(actual,expected))throw Error('Private key does NOT match the client public key. Do not deploy this combination.');
 console.log('MATCH: client/server offline RSA pair. Public SPKI SHA256: '+createHash('sha256').update(actual).digest('hex'));
}catch(error){console.error('CHECK FAILED: '+error.message);process.exit(1);}
