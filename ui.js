'use strict';
const $=id=>document.getElementById(id);let inspectedRaw=null;
const sample='From: "Accounts@bank.example" <sender@fictional.example>\nReply-To: help@other.example\nReturn-Path: bounce@fictional.example\nAuthentication-Results: mx.fictional.example; spf=fail smtp.mailfrom=fictional.example; dkim=pass header.d=fictional.example; dmarc=pass header.from=fictional.example\nAuthentication-Results: untrusted.example; spf=pass; dkim=pass; dmarc=pass\nSubject: Fictional example only\n\nAuthentication-Results: body.example; spf=pass; dkim=pass; dmarc=pass';
function node(tag,text,parent){const el=document.createElement(tag);el.textContent=text;if(parent)parent.appendChild(el);return el;}
function render(r){
 const out=$('output');out.replaceChildren();out.hidden=false;
 node('h2',r.status==='selected'?'Selected reported results':'Unverified headers',out);node('p',r.reason,out);
 node('p','No safe-message verdict is given. A pass is only a reported result, not proof of safety.',out);
 node('p','Parsed From domain: '+(r.from.domain||'unresolved'),out);
 if(r.replyTo)node('p','Parsed Reply-To domain: '+(r.replyTo.domain||'unresolved'),out);
 if(r.returnPath)node('p','Parsed Return-Path domain: '+(r.returnPath.domain||'unresolved'),out);
 const warnings=[...r.issues,...r.notes];if(warnings.length){const ul=node('ul','',out);warnings.forEach(w=>node('li',w,ul));}
 if(!r.reports.length)node('p','No Authentication-Results header found in the header section.',out);
 for(const report of r.reports){const box=node('div','',out);box.className='result';node('h3','Header '+(report.index+1)+' · '+(report.id||'unresolved authserv-id'),box);node('p',r.status==='selected'&&r.selected.index===report.index?'Selected under your stated boundary.':'Unverified report. Not merged with other headers.',box);for(const result of report.results)node('p',result.method.toUpperCase()+': reported '+result.result+(result.domain?' · '+result.domain:''),box);for(const issue of report.issues)node('p','Review: '+issue,box);node('details','',box).appendChild(node('summary','Show raw Authentication-Results'));box.lastChild.appendChild(node('pre',report.raw));}
}
function resetBoundary(){inspectedRaw=null;$('confirm').checked=false;$('trusted').value='';$('boundary').hidden=true;$('output').hidden=true;$('error').textContent='';}
$('inspect').onclick=()=>{try{const r=HeaderCheck.analyse($('raw').value);inspectedRaw=$('raw').value;$('confirm').checked=false;$('trusted').value='';$('error').textContent='';$('report').replaceChildren();r.reports.forEach(x=>{const option=node('option','Header '+(x.index+1)+' · '+(x.id||'unresolved'));option.value=String(x.index);$('report').appendChild(option);});$('boundary').hidden=!r.reports.length;render(r);}catch(e){resetBoundary();$('error').textContent=e.message;}};
$('apply').onclick=()=>{if(inspectedRaw!==$('raw').value){resetBoundary();$('error').textContent='Headers changed. Inspect them again.';return;}try{render(HeaderCheck.analyse(inspectedRaw,{index:Number($('report').value),trustedId:$('trusted').value,confirmedBoundary:$('confirm').checked}));}catch(e){$('error').textContent=e.message;}};
$('raw').oninput=resetBoundary;
for(const id of ['trusted','report'])$(id).oninput=()=>{$('confirm').checked=false;if(inspectedRaw)render(HeaderCheck.analyse(inspectedRaw));};
$('confirm').onchange=()=>{if(!$( 'confirm').checked&&inspectedRaw)render(HeaderCheck.analyse(inspectedRaw));};
$('sample').onclick=()=>{resetBoundary();$('raw').value=sample;};
$('clear').onclick=()=>{resetBoundary();$('raw').value='';$('raw').focus();};
