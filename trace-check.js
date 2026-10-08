/* Private Received-field inspection. No route authentication or delay inference. */
(function(root){
'use strict';
function splitDate(raw){let depth=0,quote=false,escape=false,pos=-1,count=0;
 for(let i=0;i<raw.length;i++){const c=raw[i];if(escape){escape=false;continue;}if(c==='\\'){escape=true;continue;}if(c==='"'&&!depth){quote=!quote;continue;}if(!quote&&c==='('){depth++;continue;}if(!quote&&c===')'){if(!depth)return null;depth--;continue;}if(c===';'&&!quote&&!depth){pos=i;count++;}}
 if(quote||depth||escape||count!==1)return null;return {route:raw.slice(0,pos).trim(),date:raw.slice(pos+1).trim()};}
function timestamp(s){
 // Only the common, numeric-offset form is supported; other forms stay raw.
 const m=s.match(/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+(\d{1,2})\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})\s+([+-])(\d{2})(\d{2})$/i);
 if(!m)return null;
 const months=['jan','feb','mar','apr','may','jun','jul','aug','sep','oct','nov','dec'];let day=+m[1],month=months.indexOf(m[2].toLowerCase()),year=+m[3],hh=+m[4],mm=+m[5],ss=+m[6],oh=+m[8],om=+m[9];
 if(year<1900||year>9999||day<1||day>31||hh>23||mm>59||ss>59||oh>23||om>59)return null;
 const local=new Date(Date.UTC(year,month,day,hh,mm,ss));if(local.getUTCMonth()!==month||local.getUTCDate()!==day)return null;
 const weekday=['Sun','Mon','Tue','Wed','Thu','Fri','Sat'][local.getUTCDay()];if(s.slice(0,3).toLowerCase()!==weekday.toLowerCase())return null;
 const offset=(oh*60+om)*(m[7]==='+'?1:-1);return new Date(local.getTime()-offset*60000).toISOString();
}
function visibleRoute(s){let out='',depth=0,quote=false,escape=false;for(const c of s){if(escape){out+=' ';escape=false;continue;}if(c==='\\'){escape=true;out+=' ';continue;}if(c==='"'&&!depth){quote=!quote;out+=' ';continue;}if(!quote&&c==='('){depth++;out+=' ';continue;}if(!quote&&c===')'){depth--;out+=' ';continue;}out+=(depth||quote)?' ':c;}return out;}
function host(s,key){const visible=visibleRoute(s);const occurrences=[...visible.matchAll(new RegExp('(?:^|\\s)'+key+'(?=\\s|$)','ig'))];if(occurrences.length!==1)return null;const re=new RegExp('(?:^|\\s)'+key+'\\s+([A-Za-z0-9][A-Za-z0-9.-]*)(?=\\s|\\(|$)','i');const matches=[...visible.matchAll(new RegExp(re.source,'ig'))];const m=matches.length===1?matches[0]:null;if(!m)return null;const name=m[1];if(name.length>253)return null;if(!name.split('.').every(x=>/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(x)))return null;return name;}
function analyse(raw){const h=root.HeaderCheck.headers(raw);return h.fields.filter(f=>f.name==='received').map((f,index)=>{const parts=splitDate(f.value);return {index,line:f.line,raw:f.value,from:parts?host(parts.route,'from'):null,by:parts?host(parts.route,'by'):null,recordedDate:parts?parts.date:null,utc:parts?timestamp(parts.date):null};});}
const api={analyse,splitDate,timestamp};root.TraceCheck=api;if(typeof module!=='undefined'&&module.exports)module.exports=api;
})(typeof globalThis!=='undefined'?globalThis:this);
