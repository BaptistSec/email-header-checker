'use strict';
const $=id=>document.getElementById(id);let inspectedRaw=null;
const sample='From: "Accounts@bank.example" <sender@fictional.example>\nReply-To: help@other.example\nReturn-Path: bounce@fictional.example\nAuthentication-Results: mx.fictional.example; spf=fail smtp.mailfrom=fictional.example; dkim=pass header.d=fictional.example; dmarc=pass header.from=fictional.example\nAuthentication-Results: untrusted.example; spf=pass; dkim=pass; dmarc=pass\nSubject: Fictional example only\n\nAuthentication-Results: body.example; spf=pass; dkim=pass; dmarc=pass';
function node(tag,text,parent){const el=document.createElement(tag);el.textContent=text;if(parent)parent.appendChild(el);return el;}
function plainReportText(text){
 if(text==='Orphan continuation line')return 'A wrapped header line has no earlier field to attach to. Ask the person managing your email to check the original details.';
 if(text.includes('SPF fail with reported DMARC pass'))return "SPF was reported as failed, but DMARC was reported as passed. This can happen when another check passes and matches the sender's domain. This tool cannot check that match.";
 if(text.includes('Reply-To domain differs'))return 'Replies go to a different domain from the visible sender. This can be genuine. Check where you intended to send your reply.';
 if(text.includes('Return-Path domain differs'))return 'The address for delivery failures has a different domain from the visible sender. This is common for bulk email and does not prove the sender is fake.';
 if(text.includes('conflicting DKIM results'))return 'The selected report gives different DKIM results for the same domain and signature name. More than one signature can be genuine. Ask the person managing your email to check each reported check.';
 if(text==='Content after the first blank line was ignored as message body.')return 'Text after the first empty line was treated as the message itself and ignored.';
 if(text.includes('selected')||text.includes('boundary')||text.includes('confirmed')||text.startsWith('Repeated authserv-id'))return 'No report has been tied to your provider. Confirm which report it added and how it removes fake reports before selecting one. A matching service name alone proves nothing.';
 return 'This report contains text the tool cannot read or details it cannot resolve. Ask the person managing your email to check the original report.';
}
function render(r){
 const out=$('output');out.replaceChildren();out.hidden=false;
 node('h2',r.status==='selected'?'Selected reported results':'Unverified headers',out);node('p',r.status==='selected'?'Showing the reported checks you selected using provider details you confirmed. The tool has not verified their origin.':plainReportText(r.reason),out);if(r.status!=='selected')node('p','Unverified means the report has not been tied to your provider. A trusted boundary means knowing which report the provider added and how it removes fakes. Any technical review message below means a person must check the original details; it is not a fraud verdict.',out);
 node('p','No safe-message verdict is given. A pass is only a reported result, not proof of safety.',out);
 node('p','From domain (part after @): '+(r.from.domain||'could not be read'),out);
 if(r.replyTo)node('p','Reply-To domain (part after @): '+(r.replyTo.domain||'could not be read'),out);
 if(r.returnPath)node('p','Return-Path domain (part after @): '+(r.returnPath.domain||'could not be read'),out);
 const warnings=[...r.issues,...r.notes];if(warnings.length){const ul=node('ul','',out);warnings.forEach(w=>node('li',plainReportText(w),ul));}
 if(!r.reports.length)node('p','No Authentication-Results header found in the header section.',out);
 for(const report of r.reports){const box=node('div','',out);box.className='result';node('h3','Header '+(report.index+1)+' · '+(report.id||'service name could not be read'),box);node('p',r.status==='selected'&&r.selected.index===report.index?'Selected using the provider details you confirmed. This does not prove the report is genuine.':'Unverified report. Not merged with other headers.',box);for(const result of report.results)node('p',result.method.toUpperCase()+': reported '+result.result+(result.domain?' · '+result.domain:''),box);for(const issue of report.issues)node('p',plainReportText(issue),box);node('details','',box).appendChild(node('summary','Show original check report (Authentication-Results)'));box.lastChild.appendChild(node('pre',report.raw));if(report.issues.length)box.lastChild.appendChild(node('pre','Technical reading notes: '+report.issues.join('; ')));}
}
function resetBoundary(){inspectedRaw=null;$('confirm').checked=false;$('trusted').value='';$('boundary').hidden=true;$('output').hidden=true;$('error').textContent='';}
$('inspect').onclick=()=>{try{const r=HeaderCheck.analyse($('raw').value);inspectedRaw=$('raw').value;$('confirm').checked=false;$('trusted').value='';$('error').textContent='';$('report').replaceChildren();r.reports.forEach(x=>{const option=node('option','Header '+(x.index+1)+' · '+(x.id||'service name could not be read'));option.value=String(x.index);$('report').appendChild(option);});$('boundary').hidden=!r.reports.length;render(r);}catch(e){resetBoundary();$('error').textContent=e.message.includes('Paste')?e.message:plainReportText(e.message);}};
$('apply').onclick=()=>{if(inspectedRaw!==$('raw').value){resetBoundary();$('error').textContent='Headers changed. Inspect them again.';return;}try{render(HeaderCheck.analyse(inspectedRaw,{index:Number($('report').value),trustedId:$('trusted').value,confirmedBoundary:$('confirm').checked}));}catch(e){$('error').textContent=e.message.includes('Paste')?e.message:plainReportText(e.message);}};
$('raw').oninput=resetBoundary;
for(const id of ['trusted','report'])$(id).oninput=()=>{$('confirm').checked=false;if(inspectedRaw)render(HeaderCheck.analyse(inspectedRaw));};
$('confirm').onchange=()=>{if(!$( 'confirm').checked&&inspectedRaw)render(HeaderCheck.analyse(inspectedRaw));};
$('sample').onclick=()=>{resetBoundary();$('raw').value=sample;};
$('clear').onclick=()=>{resetBoundary();$('raw').value='';$('raw').focus();};
