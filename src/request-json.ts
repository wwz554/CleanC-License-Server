export class RequestError extends Error {
 constructor(public status:number,message:string){super(message);}
}
/** Bound actual streamed bytes, not the optional/untrusted Content-Length header. */
export async function readJsonObject(request:Request,maximumBytes=12000):Promise<Record<string,unknown>>{
 if(!/^application\/json(?:\s*;|$)/i.test(request.headers.get('content-type')||''))throw new RequestError(415,'请求必须使用 JSON 格式。');
 if(Number(request.headers.get('content-length'))>maximumBytes)throw new RequestError(413,'请求过大。');
 const reader=request.body?.getReader();if(!reader)throw new RequestError(400,'请求为空。');
 const chunks:Uint8Array[]=[];let length=0;
 try{
  for(;;){const {value,done}=await reader.read();if(done)break;length+=value.byteLength;if(length>maximumBytes){await reader.cancel();throw new RequestError(413,'请求过大。');}chunks.push(value);}
 }finally{reader.releaseLock();}
 const bytes=new Uint8Array(length);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
 let body:unknown;try{body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{throw new RequestError(400,'JSON 请求无效。');}
 if(!body||typeof body!=='object'||Array.isArray(body))throw new RequestError(400,'请求必须是 JSON 对象。');
 return body as Record<string,unknown>;
}
export function normalizePem(pem:string):string{return pem.replace(/\\r\\n/g,'\n').replace(/\\n/g,'\n').trim();}
