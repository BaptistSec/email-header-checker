function tddUnfold(t){return t.replace(/\r\n?/g,'\n').replace(/\n[ \t]+/g,' ');}
function tddDomain(v){if(!v)return '';var m=v.match(/@([A-Za-z0-9.\-]+)/);return m?m[1].toLowerCase().replace(/\.$/,''):'';}
function tddHeader(lines,name){var r=[],re=new RegExp('^'+name+':\\s*(.*)$','i');lines.forEach(function(l){var m=l.match(re);if(m)r.push(m[1]);});return r;}
function tddAnalyse(raw){
 var lines=tddUnfold(raw).split('\n');
 var ar=tddHeader(lines,'Authentication-Results');
 var res={spf:[],dkim:[],dmarc:[]};
 ar.forEach(function(h,i){
  h.split(';').slice(1).forEach(function(p){
   var m=p.trim().match(/^(spf|dkim|dmarc)\s*=\s*([a-z]+)/i);
   if(m){var d=p.match(/(?:header\.d|header\.from|smtp\.mailfrom)\s*=\s*"?([^\s";()]+)/i);
    res[m[1].toLowerCase()].push({r:m[2].toLowerCase(),d:d?d[1].toLowerCase():'',top:i===0});}
  });
 });
 var from=tddDomain((tddHeader(lines,'From')[0]||'')),
  rp=tddDomain((tddHeader(lines,'Return-Path')[0]||'')),
  rt=tddDomain((tddHeader(lines,'Reply-To')[0]||''));
 var notes=[];
 if(!ar.length)notes.push({lvl:'warn',t:'No Authentication-Results header found. Your mail provider may not add one, or the header was not copied in full.'});
 ['spf','dkim','dmarc'].forEach(function(k){
  if(ar.length&&!res[k].length)notes.push({lvl:'warn',t:k.toUpperCase()+' result not present in the header.'});
  res[k].forEach(function(x){
   if(x.r==='fail')notes.push({lvl:'bad',t:k.toUpperCase()+' failed'+(x.d?' for '+x.d:'')+'. Treat this message with suspicion.'});
   else if(x.r==='softfail'||x.r==='temperror'||x.r==='permerror')notes.push({lvl:'warn',t:k.toUpperCase()+' returned '+x.r+(x.d?' for '+x.d:'')+'.'});
  });
 });
 if(from&&rp&&from!==rp&&!(from.slice(-rp.length-1)==='.'+rp||rp.slice(-from.length-1)==='.'+from))
  notes.push({lvl:'info',t:'From domain ('+from+') differs from Return-Path domain ('+rp+'). Common for newsletters and bulk senders, but also seen in spoofing.'});
 if(from&&rt&&from!==rt)notes.push({lvl:'warn',t:'Reply-To domain ('+rt+') differs from From domain ('+from+'). Replies would go somewhere else.'});
 var allPass=['spf','dkim','dmarc'].every(function(k){return res[k].some(function(x){return x.r==='pass';});});
 var anyFail=['spf','dkim','dmarc'].some(function(k){return res[k].some(function(x){return x.r==='fail';});});
 var verdict=anyFail?'bad':(allPass&&!notes.some(function(n){return n.lvl==='warn';})?'good':'mixed');
 return {res:res,from:from,rp:rp,rt:rt,notes:notes,verdict:verdict,hasAR:ar.length>0};
}
