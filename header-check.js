/* Email Header Checker 2.0. Conservative inspection, not message authentication. */
(function(root){
'use strict';
const MAX=200000;
function splitSyntax(s,delimiter){
 let out=[],part='',quote=false,escape=false,depth=0;
 for(const c of s){
  if(escape){part+=c;escape=false;continue;}
  if(c==='\\'){part+=c;escape=true;continue;}
  if(c==='"'&&depth===0){quote=!quote;part+=c;continue;}
  if(!quote&&c==='('){depth++;part+=c;continue;}
  if(!quote&&c===')'){if(!depth)throw Error('Unbalanced comment');depth--;part+=c;continue;}
  if(c===delimiter&&!quote&&!depth){out.push(part);part='';}else part+=c;
 }
 if(quote||depth||escape)throw Error('Unclosed quote, comment or escape');
 out.push(part);return out;
}
function removeComments(s){
 let out='',quote=false,depth=0,esc=false;
 for(const c of s){
  if(esc){if(!depth)out+=c;esc=false;continue;}
  if(c==='\\'){if(!depth)out+=c;esc=true;continue;}
  if(c==='"'&&!depth){quote=!quote;out+=c;continue;}
  if(!quote&&c==='('){depth++;out+=' ';continue;}
  if(!quote&&c===')'){depth--;continue;}
  if(!depth)out+=c;
 }return out;
}
function domain(s){
 if(typeof s!=='string')return null;
 s=s.toLowerCase().replace(/\.$/,'');
 if(s.length>253||!s.includes('.')||!s.split('.').every(p=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(p)))return null;
 return s;
}
function mailbox(s){
 if(!s)return {domain:null,issue:'Missing address'};
 try{splitSyntax(s,';');s=removeComments(s);}catch(e){return {domain:null,issue:e.message};}
 let quote=false,esc=false,unquoted='',angles=[];
 for(let i=0;i<s.length;i++){const c=s[i];
  if(esc){esc=false;continue;}
  if(c==='\\'){esc=true;continue;}
  if(c==='"'){quote=!quote;continue;}
  if(!quote){unquoted+=c;if(c==='<'||c==='>')angles.push({char:c,index:i});}
 }
 if(unquoted.includes(',')||unquoted.includes(':')||unquoted.includes(';'))return {domain:null,issue:'Multiple addresses or group syntax: inspect manually'};
 let addr;
 if(angles.length){
  if(angles.length!==2||angles[0].char!=='<'||angles[1].char!=='>'||s.slice(angles[1].index+1).trim())return {domain:null,issue:'Unbalanced or ambiguous angle address'};
  const display=s.slice(0,angles[0].index).trim();
  if(display&&!/^(?:"(?:[^"\\\r\n]|\\[ -~])*"|[a-zA-Z0-9!#$%&'*+\-/=?^_`{|}~]+(?:\s+[a-zA-Z0-9!#$%&'*+\-/=?^_`{|}~]+)*)$/.test(display))return {domain:null,issue:'Unsupported display-name syntax'};
  addr=s.slice(angles[0].index+1,angles[1].index).trim();
 }else addr=s.trim();
 const m=addr.match(/^[a-zA-Z0-9!#$%&'*+\-/=?^_`{|}~]+(?:\.[a-zA-Z0-9!#$%&'*+\-/=?^_`{|}~]+)*@([^\s@]+)$/);
 const d=m&&domain(m[1]);return d?{domain:d,issue:null}:{domain:null,issue:'Unsupported or malformed mailbox: inspect manually'};
}
function headers(raw){
 if(typeof raw!=='string'||raw.length>MAX)throw Error('Paste at most 200,000 characters.');
 if(!raw.trim())throw Error('Paste message headers first.');
 if(/\u0000/.test(raw))throw Error('NUL characters are unsupported.');
 const lines=raw.replace(/\r\n/g,'\n').replace(/\r/g,'\n').split('\n');
 const fields=[],issues=[];let current=null,bodyIgnored=false;
 for(let i=0;i<lines.length;i++){
  const line=lines[i];if(line===''){bodyIgnored=i<lines.length-1;break;}
  if(/^[ \t]/.test(line)){if(current)current.value+=' '+line.trim();else issues.push('Orphan continuation line');continue;}
  const m=line.match(/^([!-9;-~]+):[ \t]*(.*)$/);
  if(!m){issues.push('Unsupported header line '+(i+1));current=null;continue;}
  current={name:m[1].toLowerCase(),value:m[2],line:i+1};fields.push(current);
 }return {fields,issues,bodyIgnored};
}
function auth(value,index){
 const item={index,id:null,version:null,results:[],issues:[],raw:value};
 try{
  const parts=splitSyntax(value,';').map(removeComments);
  const id=parts.shift().trim().match(/^(?:"([a-zA-Z0-9._-]+)"|([a-zA-Z0-9._-]+))(?:\s+(\d+))?$/);
  if(!id)throw Error('Unsupported authserv-id syntax');item.id=(id[1]||id[2]).toLowerCase();item.version=id[3]||'1';
  if(item.version!=='1')item.issues.push('Unsupported Authentication-Results version');
  if(parts.length===1&&parts[0].trim()==='none')return item;
  if(!parts.length)throw Error('No result clauses');
  for(const part of parts){
   const clause=part.trim();
   const m=clause.match(/^([a-zA-Z0-9][a-zA-Z0-9-]*)(?:\/(\d+))?\s*=\s*([a-zA-Z]+)(?:\s|$)/);
   if(!m){item.issues.push('Malformed or unsupported result clause');continue;}
   const method=m[1].toLowerCase(),result=m[3].toLowerCase();
   const supported=['spf','dkim','dmarc'].includes(method);
   if(!supported)item.issues.push('Unsupported authentication method '+method);
   const allowed={spf:['pass','fail','softfail','neutral','none','temperror','permerror'],dkim:['pass','fail','policy','neutral','none','temperror','permerror'],dmarc:['pass','fail','none','temperror','permerror']};
   if(!(allowed[method]||['pass','fail','softfail','neutral','none','temperror','permerror','policy']).includes(result))item.issues.push('Unknown '+method.toUpperCase()+' result');
   if(m[2]&&m[2]!=='1')item.issues.push('Unsupported '+method.toUpperCase()+' method version');
   let tail=clause.slice(m[0].length);const properties={};let sawProperty=false;
   while(tail.trim()){
    tail=tail.trimStart();
    const token=tail.match(/^(reason|[a-zA-Z0-9][a-zA-Z0-9-]*\s*\.\s*[a-zA-Z0-9][a-zA-Z0-9-]*)\s*=\s*("(?:[^"\\\r\n]|\\[ -~])*"|[a-zA-Z0-9!#$%&'*+\-.^_`{|}~@]+)(?=\s|$)/);
    if(!token){item.issues.push('Unsupported result property syntax');break;}
    const key=token[1].replace(/\s/g,'').toLowerCase();let v=token[2];
    if(key==='reason'&&sawProperty)item.issues.push('Reason must precede properties');
    if(key!=='reason')sawProperty=true;
    if(Object.hasOwn(properties,key))item.issues.push('Duplicate result property '+key);
    const quoted=v.startsWith('"');
    if(quoted)v=v.slice(1,-1).replace(/\\(.)/g,'$1');
    if(key==='reason'){
     if(!quoted&&!/^[\x21-\x7e]+$/.test(v))item.issues.push('Unsupported reason token');
     if(!quoted&&/[()<>@,;:\\"/\[\]?=]/.test(v))item.issues.push('Reason must be a MIME token or quoted string');
    }else if(v.includes('@')){
     const at=v.indexOf('@');const local=v.slice(0,at),host=v.slice(at+1);
     if(v.lastIndexOf('@')!==at||!domain(host)||(local&&!mailbox(v).domain))item.issues.push('Unsupported address property');
    }else if(!quoted&&/[()<>@,;:\\"/\[\]?=]/.test(v))item.issues.push('Unsupported property value token');
    if(/[\x00-\x1f\x7f]/.test(v))item.issues.push('Unsupported control character in property');
    properties[key]=v;tail=tail.slice(token[0].length);
   }
   if(!supported)continue;
   const key={spf:'smtp.mailfrom',dkim:'header.d',dmarc:'header.from'}[method];let d=null;
   if(properties[key])d=method==='spf'&&properties[key].includes('@')?mailbox(properties[key]).domain:domain(properties[key]);
   if(properties[key]&&!d)item.issues.push('Unsupported '+key+' domain');
   item.results.push({method,result,domain:d,properties});
  }
 }catch(e){item.issues.push(e.message);}return item;
}
function analyse(raw,options={}){
 const parsed=headers(raw);const list=name=>parsed.fields.filter(f=>f.name===name);
 const reports=list('authentication-results').map((f,i)=>({...auth(f.value,i),line:f.line}));
 const issues=[...parsed.issues];
 const address=name=>{const rows=list(name);if(rows.length!==1){if(rows.length>1)issues.push('Duplicate '+name+' headers');return {domain:null,issue:rows.length?'Duplicate address headers':'Missing address'};}return mailbox(rows[0].value);};
 const from=address('from'),reply=list('reply-to').length?address('reply-to'):null,rp=list('return-path').length?address('return-path'):null;
 if(from.issue)issues.push('From: '+from.issue);if(reply?.issue)issues.push('Reply-To: '+reply.issue);if(rp?.issue)issues.push('Return-Path: '+rp.issue);
 const selected=Number.isInteger(options.index)?reports[options.index]:null;
 const id=typeof options.trustedId==='string'?options.trustedId.trim().toLowerCase():'';
 const matching=reports.filter(r=>r.id===id);
 let status='unverified';let reason='Pasted headers cannot establish who added a result. No trusted boundary is selected.';
 if(options.confirmedBoundary===true&&selected&&id&&selected.id===id){
  if(matching.length!==1){reason='Repeated authserv-id: cannot resolve the trusted result from text alone.';}
  else if(issues.length||selected.issues.length){reason='Malformed or unsupported syntax: selected result needs manual review.';}
  else{status='selected';reason='Showing the selected reported results under your stated trust boundary. This tool has not authenticated that boundary.';}
 }
 const notes=[];
 if(selected){const identities=new Map();for(const r of selected.results.filter(r=>r.method==='dkim'&&r.domain)){const key=r.domain+'|'+(r.properties['header.s']||'');const prior=identities.get(key);if(prior&&prior!==r.result)notes.push('Review: conflicting DKIM results for '+r.domain+'. Multiple signatures can be legitimate; inspect each report.');identities.set(key,r.result);}}
 if(reply?.domain&&from.domain&&reply.domain!==from.domain)notes.push('Reply-To domain differs from From. This may be legitimate; verify the intended reply route.');
 if(rp?.domain&&from.domain&&rp.domain!==from.domain)notes.push('Return-Path domain differs from From. This is common for bulk mail and is not proof of spoofing.');
 if(selected){
  const dm=selected.results.filter(r=>r.method==='dmarc');
  if(dm.length>1||selected.results.filter(r=>r.method==='spf').length>1){status='unverified';reason='Multiple SPF or DMARC clauses require manual review.';}
  if(dm.some(r=>r.result==='pass')&&dm.some(r=>r.result==='fail')){status='unverified';reason='Conflicting DMARC clauses require manual review.';}
  if(dm.some(r=>r.result==='pass')&&selected.results.some(r=>r.method==='spf'&&r.result==='fail'))notes.push('SPF fail with reported DMARC pass can occur if another aligned mechanism passes. The tool does not compute alignment or verify that explanation.');
  if(dm.some(r=>r.domain&&from.domain&&r.domain!==from.domain)){status='unverified';reason='Reported DMARC From domain differs from parsed From. Review the source and syntax.';}
 }
 if(parsed.bodyIgnored)notes.push('Content after the first blank line was ignored as message body.');
 return {status,reason,reports,selected:selected||null,from,replyTo:reply,returnPath:rp,issues,notes,bodyIgnored:parsed.bodyIgnored};
}
const api={analyse,headers,auth,mailbox,MAX};if(typeof module!=='undefined'&&module.exports)module.exports=api;root.HeaderCheck=api;
})(typeof globalThis!=='undefined'?globalThis:this);
