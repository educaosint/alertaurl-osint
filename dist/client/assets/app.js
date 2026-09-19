const $=s=>document.querySelector(s),form=$('#risk-form'),button=$('#analyze-button');
const risky=/(?:login|verify|verification|seguridad|secure|premio|gift|oferta|soporte|support|actualiza|update|wallet|bonus|free|ganador|claim)/i;
const shorteners=new Set(['bit.ly','tinyurl.com','t.co','cutt.ly','is.gd','rb.gy','rebrand.ly','shorturl.at','sw.run','ow.ly','buff.ly','lnkd.in','goo.gl']);
const social={'instagram.com':'Instagram','www.instagram.com':'Instagram','facebook.com':'Facebook','www.facebook.com':'Facebook','fb.com':'Facebook','www.fb.com':'Facebook','m.facebook.com':'Facebook'};
const hostedPlatforms=['netlify.app','vercel.app','pages.dev','github.io','firebaseapp.com','web.app','wixsite.com','weebly.com','blogspot.com'];
const brands=[
  {name:'Meta / Facebook',tokens:['meta','facebook','fb-business','accountquality'],domains:['facebook.com','meta.com','fb.com']},
  {name:'Banco Popular Dominicano',tokens:['banco-popular','bancopopular','popularenlinea'],domains:['popularenlinea.com']},
  {name:'Banreservas',tokens:['banreservas','banco-reservas'],domains:['banreservas.com']},
  {name:'Banco BHD',tokens:['banco-bhd','bancobhd','bhd'],domains:['bhd.com.do']},
  {name:'Scotiabank',tokens:['scotiabank','scotia-bank'],domains:['scotiabank.com','scotiabank.com.do']},
  {name:'APAP',tokens:['apap','asociacion-popular'],domains:['apap.com.do']},
  {name:'Banco Santa Cruz',tokens:['banco-santacruz','bancosantacruz'],domains:['bsc.com.do']},
  {name:'Banco Promerica',tokens:['promerica','banco-promerica'],domains:['promerica.com.do']},
  {name:'Bank of America',tokens:['bankofamerica','bank-of-america','bofa'],domains:['bankofamerica.com']},
  {name:'Chase',tokens:['chase-bank','chasebank','jpmorgan-chase'],domains:['chase.com','jpmorgan.com']},
  {name:'Wells Fargo',tokens:['wellsfargo','wells-fargo'],domains:['wellsfargo.com']},
  {name:'Citibank',tokens:['citibank','citi-bank'],domains:['citi.com','citibank.com']},
  {name:'Santander',tokens:['santander','banco-santander'],domains:['santander.com']}
];
const safe=v=>String(v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const belongsTo=(host,domain)=>host===domain||host.endsWith(`.${domain}`);
const categoryLabels={suplantacion:'Suplantación',phishing:'Phishing',estafa:'Posible estafa',apuestas:'Apuestas',armas:'Venta de armas',contenido_ilicito:'Contenido potencialmente ilícito',publicidad_enganosa:'Publicidad engañosa',otro:'Otra alerta'};
const autoCheckLabels={redirects:'Redirecciones',link:'Tipo de enlace',dns:'Dominio y DNS',content:'Apuestas y armas',popups:'Pop-ups engañosos',brands:'Bancos y marcas'};

function setAutoChecks(mode='neutral',checks=[]){
  const find=(patterns)=>checks.find(([name])=>patterns.some(pattern=>pattern.test(name)));
  const states={
    redirects:find([/Redirecci/i,/Cambio de dominio/i]),
    link:find([/Tipo detectado/i,/Análisis profundo/i]),
    dns:find([/Dominio en DNS/i,/Datos del dominio/i]),
    content:find([/Apuestas, armas/i,/Contenido detectado/i]),
    popups:find([/Pop-ups/i,/Ventanas emergentes/i]),
    brands:find([/marca suplantada/i,/Dominio de marca/i,/Bancos y marcas/i])
  };
  document.querySelectorAll('[data-auto-check]').forEach(chip=>{
    const key=chip.dataset.autoCheck,label=autoCheckLabels[key],result=states[key];
    chip.className='';
    if(mode==='checking'){chip.classList.add('checking');chip.textContent=`◌ ${label}`;chip.title='Comprobando…';return;}
    if(mode==='error'){chip.classList.add('warning');chip.textContent=`! ${label}`;chip.title='No se pudo completar esta comprobación.';return;}
    if(mode==='neutral'){chip.textContent=`○ ${label}`;chip.title='Se comprobará al iniciar el análisis.';return;}
    if(!result){chip.classList.add('warning');chip.textContent=`! ${label}`;chip.title='Comprobación limitada o sin datos suficientes.';return;}
    const [,value,state]=result,visual=state==='danger'?'danger':state==='ok'?'safe':'warning',icon=visual==='danger'?'⚠':visual==='safe'?'✓':'!';
    chip.classList.add(visual);chip.textContent=`${icon} ${label}`;chip.title=String(value||'Comprobación completada');
  });
}

function normalize(input){
  const clean=input.trim();
  if(!clean)throw new Error('Escribe o pega una dirección para analizar.');
  if(clean.startsWith('@'))return{kind:'username',username:clean.slice(1),display:clean};
  const url=new URL(/^https?:\/\//i.test(clean)?clean:`https://${clean}`);
  if(!['http:','https:'].includes(url.protocol))throw new Error('Solo se pueden analizar enlaces web.');
  return{kind:'url',url,display:clean};
}

function baseSignals(target){
  let score=0;const findings=[],checks=[],details=[];
  if(target.kind==='username'){
    checks.push(['Tipo detectado','Usuario sin plataforma','limited']);
    if(!/^[a-z0-9._-]{2,30}$/i.test(target.username)){score+=22;findings.push('El usuario contiene caracteres o una longitud poco habitual.')}
    if(/(?:oficial|official|soporte|support|ayuda|backup|new|nuevo)[._-]?\d*$/i.test(target.username)){score+=18;findings.push('El usuario usa palabras o terminaciones frecuentes en cuentas imitadoras.')}
    findings.push('Un usuario sin plataforma no permite confirmar dónde está publicado. Pega la URL completa para una revisión más precisa.');
    details.push(['Entrada recibida',target.display],['Tipo de entrada','Nombre de usuario sin plataforma identificada']);
    return{score,findings,checks,details,host:null};
  }
  const {url}=target,host=url.hostname.replace(/^www\./,'').toLowerCase(),platform=social[url.hostname.toLowerCase()]||social[host]||'Página web';
  const full=`${host}${decodeURIComponent(url.pathname)}${decodeURIComponent(url.search)}`.toLowerCase();
  details.push(['Dirección ingresada',target.display],['Dominio real',host],['Protocolo',url.protocol.replace(':','').toUpperCase()],['Ruta analizada',url.pathname+(url.search||'')]);
  checks.push(['Tipo detectado',platform,'ok']);
  if(url.protocol!=='https:'){score+=18;findings.push('La dirección no usa HTTPS. La información puede viajar con menos protección.');checks.push(['Conexión HTTPS','No disponible','danger']);}
  else checks.push(['Conexión HTTPS','Disponible','ok']);
  if(shorteners.has(host)){score+=35;findings.push('Es un enlace acortado: oculta el destino final. No continúes hasta conocer la dirección real.');checks.push(['Redirección oculta','Detectada','danger']);}
  if(/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)){score+=30;findings.push('La web usa una dirección numérica en lugar de un dominio reconocible.');}
  if(host.includes('xn--')){score+=24;findings.push('El dominio contiene caracteres codificados que podrían imitar letras de otra marca.');}
  if(risky.test(host)){score+=15;findings.push('El dominio contiene palabras usadas frecuentemente para provocar confianza o urgencia.');}
  if(host.split('.').length>4){score+=10;findings.push('La dirección tiene muchos niveles antes del dominio principal y puede resultar confusa.');}
  if((host==='docs.google.com'&&url.pathname.startsWith('/forms/'))||host==='forms.gle'){
    score+=30;findings.push('Es un formulario público de Google. Que esté alojado en Google no significa que pertenezca a Meta, un banco o la empresa mencionada.');checks.push(['Formulario público','No es canal oficial','danger']);
  }
  const hosting=hostedPlatforms.find(domain=>belongsTo(host,domain));
  if(hosting){score+=22;findings.push(`La página está alojada en ${hosting}, un servicio donde cualquier persona puede publicar. Esto no demuestra relación con la marca que aparece en pantalla.`);checks.push(['Alojamiento compartido',hosting,'danger']);}
  for(const brand of brands){
    const claimed=brand.tokens.some(token=>full.includes(token));
    const official=brand.domains.some(domain=>belongsTo(host,domain));
    if(claimed&&!official){
      score+=45;findings.push(`La dirección menciona o aparenta pertenecer a ${brand.name}, pero el dominio real no coincide con sus dominios oficiales conocidos.`);checks.push(['Posible marca suplantada',brand.name,'danger']);break;
    }
    if(official){checks.push(['Dominio de marca reconocido',brand.name,'ok']);break;}
  }
  if(/(?:https?:\/\/|www\.|\.com\/|\.do\/)/i.test(url.pathname+url.search)){
    score+=18;findings.push('La ruta contiene otra dirección o nombre de dominio como texto decorativo. El dominio real siempre está antes de la primera “/”.');
  }
  if((host.includes('instagram')&&!/^(?:www\.)?instagram\.com$/.test(url.hostname))||(host.includes('facebook')&&!/^(?:www\.|m\.)?(?:facebook|fb)\.com$/.test(url.hostname))){score+=38;findings.push('El nombre de una red social aparece dentro de un dominio que no pertenece a esa plataforma.');}
  if(platform!=='Página web'){
    const path=url.pathname.split('/').filter(Boolean);
    if(!path.length)findings.push('El enlace abre la plataforma, pero no identifica un perfil concreto.');
    if(path.some(part=>risky.test(part))){score+=8;findings.push('El nombre del perfil contiene términos que conviene contrastar con la cuenta oficial.');}
  }
  if(!checks.some(([name])=>/marca/i.test(name)))checks.push(['Bancos y marcas','Sin coincidencias evidentes','ok']);
  return{score,findings,checks,details,host};
}

async function fetchJson(url,timeout=6500){
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),timeout);
  try{const response=await fetch(url,{signal:controller.signal,headers:{accept:'application/json'}});if(!response.ok)throw new Error('unavailable');return await response.json();}
  finally{clearTimeout(timer);}
}

async function technicalChecks(host){
  const checks=[],findings=[],details=[];let score=0;
  if(!host||social[host]){checks.push(['Datos del dominio',host?'Gestionados por la plataforma':'Falta la plataforma','neutral']);details.push(['Consulta de registro',host?'La plataforma administra el dominio principal.':'Se necesita la URL completa para consultar el dominio.']);return{checks,findings,details,score};}
  const [dns,rdap]=await Promise.allSettled([
    fetchJson(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`),
    fetchJson(`https://rdap.org/domain/${encodeURIComponent(host)}`)
  ]);
  if(dns.status==='fulfilled'&&Array.isArray(dns.value.Answer)&&dns.value.Answer.length){checks.push(['Dominio en DNS','Encontrado','ok']);const records=dns.value.Answer.filter(item=>item.type===1).map(item=>item.data);details.push(['Registros DNS públicos',records.length?records.join(', '):`${dns.value.Answer.length} registro(s) disponible(s)`]);}
  else{score+=24;findings.push('No fue posible confirmar que el dominio tenga una dirección activa en DNS.');checks.push(['Dominio en DNS','No confirmado','danger']);}
  if(rdap.status==='fulfilled'){
    const event=(rdap.value.events||[]).find(item=>item.eventAction==='registration');
    if(event?.eventDate){
      const created=new Date(event.eventDate),days=Math.max(0,Math.floor((Date.now()-created.getTime())/86400000));
      const age=days<60?`${days} días`:days<730?`${Math.floor(days/30)} meses`:`${Math.floor(days/365)} años`;
      checks.push(['Antigüedad del dominio',age,days<90?'danger':'ok']);
      details.push(['Fecha de registro',created.toLocaleDateString('es-DO',{year:'numeric',month:'long',day:'numeric'})],['Antigüedad calculada',age]);
      if(days<30){score+=32;findings.push(`El dominio fue registrado hace aproximadamente ${days} días. Los dominios muy recientes requieren precaución.`);}
      else if(days<90){score+=20;findings.push('El dominio tiene menos de tres meses. Confirma la identidad del comercio por otra vía.');}
      else if(days<365){score+=8;findings.push('El dominio tiene menos de un año; esto no implica fraude, pero conviene contrastarlo.');}
    }else checks.push(['Antigüedad del dominio','No publicada','neutral']);
  }else checks.push(['Antigüedad del dominio','No disponible','neutral']);
  return{checks,findings,details,score};
}

async function deepChecks(target){
  const checks=[],findings=[],details=[];let score=0;
  if(target.kind!=='url'){checks.push(['Análisis profundo','Requiere URL completa','neutral']);return{checks,findings,details,score};}
  try{
    const response=await fetch('/api/analyze-url',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({url:target.url.href})});
    const data=await response.json();
    if(!response.ok)throw new Error(data.error||'No disponible');
    const redirects=Math.max(0,(data.chain||[]).length-1);
    checks.push(['Redirecciones',redirects?String(redirects):'No detectadas',redirects?'danger':'ok']);
    if(data.crossDomain)checks.push(['Cambio de dominio',`${data.domains.length} dominios`,'danger']);
    else checks.push(['Dominio final',new URL(data.finalUrl).hostname,'ok']);
    checks.push(['Apuestas, armas e ilícitos',data.categories?.length?data.categories.join(', '):'No detectados',data.categories?.length?'danger':'ok']);
    if(data.popups)checks.push(['Ventanas emergentes',String(data.popups),data.popups>1?'danger':'neutral']);
    else checks.push(['Pop-ups automáticos','No detectados','ok']);
    details.push(['Dirección final',data.finalUrl],['Respuesta del servidor',`HTTP ${data.status||'no disponible'}`],['Tipo de contenido',data.contentType||'No informado']);
    if(data.hops?.length)data.hops.forEach((hop,index)=>details.push([`Salto ${index+1}`,`HTTP ${hop.status} · ${hop.url}${hop.location?` → ${hop.location}`:''}`]));
    const page=data.pageInfo||{};
    if(page.title)details.push(['Título publicado por la página',page.title]);
    if(page.description)details.push(['Descripción pública',page.description]);
    details.push(['Formularios encontrados',String(page.forms||0)],['Campos de contraseña',String(page.passwordFields||0)],['Campos potencialmente sensibles',String(page.sensitiveFields||0)],['Enlaces externos',`${page.externalLinks||0} enlace(s) hacia ${page.externalDomains?.length||0} dominio(s) diferente(s)`],['Contenido HTML examinado',`${Math.round((page.htmlBytes||0)/1024)} KB`]);
    if(page.externalDomains?.length)details.push(['Dominios externos enlazados',page.externalDomains.join(', ')]);
    if(redirects)findings.push(`La dirección termina en ${new URL(data.finalUrl).hostname} después de ${redirects} redirección(es).`);
    findings.push(...(data.signals||[]));
    score+=Number(data.score)||0;
  }catch(error){
    checks.push(['Análisis profundo','No disponible','neutral']);
    findings.push(`No se pudo abrir el contenido automáticamente: ${error.message}. Las demás comprobaciones sí fueron aplicadas.`);
    details.push(['Limitación encontrada',error.message]);
  }
  return{checks,findings,details,score};
}

function render(score,findings,checks,details,target){
  score=Math.min(100,Math.max(0,score));let level,title,summary,color;
  if(score>=60){level='RIESGO ALTO';title='No continúes sin verificar por otro canal';color='#ff6b6b';summary='Encontramos señales fuertes compatibles con un enlace engañoso o una posible suplantación. No pagues ni compartas datos o códigos.';}
  else if(score>=30){level='PRECAUCIÓN';title='Hay señales que debes confirmar';color='#ffbd59';summary='La revisión encontró elementos que requieren comprobación. Busca el negocio por tu cuenta y contacta su canal oficial antes de continuar.';}
  else{level='SIN ALERTAS TÉCNICAS EVIDENTES';title='No detectamos señales fuertes en esta revisión';color='#69e6d1';summary='Esto no significa que la cuenta o tienda sea legítima. Confirma el beneficiario, la oferta y el canal oficial antes de pagar.';}
  $('#score').textContent=score;$('#score-ring').style.background=`conic-gradient(${color} ${score}%,#17313e 0)`;$('#risk-label').textContent=level;$('#risk-label').style.color=color;$('#result-title').textContent=title;$('#result-summary').textContent=summary;
  $('#analysis-meta').innerHTML=checks.map(([name,value,state])=>`<div class="meta-card ${state}"><small>${safe(name)}</small><b>${safe(value)}</b></div>`).join('');
  const messages=findings.length?findings:['No encontramos anomalías visibles en la dirección. Una web técnicamente correcta también puede utilizarse para estafar.'];
  $('#signals').innerHTML=messages.map(message=>`<div class="signal">${safe(message)}</div>`).join('');
  $('#detail-list').innerHTML=details.map(([label,value],index)=>`<div class="detail-row"><span>${safe(label)}</span><b>${safe(value||'No disponible')}</b></div>`).join('');
  $('#detail-count').textContent=`${details.length} dato${details.length===1?'':'s'}`;
  $('#detail-panel').hidden=!details.length;
  $('#detail-panel').open=false;
  setAutoChecks('result',checks);
  $('#result').hidden=false;$('#result').dataset.report=`ALERTAURL OSINT — Educa OSINT\nConsulta: ${target.display}\n${level}: ${score}/100\n${title}\n\nSEÑALES ENCONTRADAS\n- ${messages.join('\n- ')}\n\nDETALLE TÉCNICO\n${details.map(([label,value])=>`${label}: ${value||'No disponible'}`).join('\n')}\n\nEste informe es orientativo y no certifica la legitimidad ni la ilegalidad de una página.`;$('#result').scrollIntoView({behavior:'smooth',block:'center'});
}
let existingAnalyzedReport=null;
async function checkExistingReport(url){
  if(!url)return null;
  const known=reportCache.find(report=>reportUrlKey(report.canonical_url)===reportUrlKey(url));
  if(known)return known;
  try{
    const response=await fetch('/api/reports/check',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({url})}),data=await response.json();
    return response.ok&&data.reported?data.report:null;
  }catch{return null;}
}
function updateReportAction(report=null){
  existingAnalyzedReport=report;
  const reportButton=$('#show-report-form'),viewButton=$('#view-existing-report'),badge=$('#reported-badge');
  reportButton.hidden=!!report;reportButton.disabled=!!report;reportButton.textContent='Reportar una página';
  reportButton.title=report?'Esta dirección ya tiene un reporte comunitario.':'';
  badge.hidden=!report;
  viewButton.hidden=!report;
  if(report)$('#report-form').hidden=true;
}

form.addEventListener('submit',async event=>{
  event.preventDefault();$('#result').hidden=true;setAutoChecks('checking');button.disabled=true;button.innerHTML='Analizando…';
  try{
    const target=normalize($('#target').value),base=baseSignals(target);
    const[tech,deep,existing]=await Promise.all([technicalChecks(base.host),deepChecks(target),target.kind==='url'?checkExistingReport(target.url.href):Promise.resolve(null)]);
    render(base.score+tech.score+deep.score,[...base.findings,...tech.findings,...deep.findings],[...base.checks,...tech.checks,...deep.checks],[...base.details,...tech.details,...deep.details],target);
    updateReportAction(existing);
  }
  catch(error){updateReportAction();setAutoChecks('error');$('#result').hidden=false;$('#detail-panel').hidden=true;$('#detail-list').innerHTML='';$('#risk-label').textContent='NO SE PUDO ANALIZAR';$('#risk-label').style.color='#ffbd59';$('#result-title').textContent='Revisa la dirección ingresada';$('#result-summary').textContent=error.message||'Pega una URL válida e inténtalo otra vez.';$('#analysis-meta').innerHTML='';$('#signals').innerHTML='';$('#score').textContent='—';$('#score-ring').style.background='#17313e';}
  finally{button.disabled=false;button.innerHTML='Analizar ahora <span>→</span>';}
});
$('#new-analysis').addEventListener('click',()=>{$('#result').hidden=true;updateReportAction();setAutoChecks();form.reset();$('#target').focus();scrollTo({top:document.querySelector('.scanner').offsetTop-20,behavior:'smooth'});});
$('#clear-button').addEventListener('click',()=>{$('#result').hidden=true;updateReportAction();setAutoChecks();form.reset();$('#target').value='';$('#target').focus();});
$('#copy-report').addEventListener('click',async()=>{try{await navigator.clipboard.writeText($('#result').dataset.report||'');$('#copy-report').textContent='Informe copiado';setTimeout(()=>$('#copy-report').textContent='Copiar informe',1800);}catch{$('#copy-report').textContent='No se pudo copiar';}});
$('#download-report').addEventListener('click',()=>{
  const content=$('#result').dataset.report||'';
  if(!content)return;
  const blob=new Blob([content],{type:'text/plain;charset=utf-8'}),url=URL.createObjectURL(blob),link=document.createElement('a');
  link.href=url;link.download=`informe-alertaurl-osint-${new Date().toISOString().slice(0,10)}.txt`;document.body.appendChild(link);link.click();link.remove();URL.revokeObjectURL(url);
});

function votedReports(){try{return JSON.parse(localStorage.getItem('alertaurl_votes')||localStorage.getItem('verifica_votes')||'{}');}catch{return{};}}
function rememberVote(id){try{const votes=votedReports();votes[id]=true;localStorage.setItem('alertaurl_votes',JSON.stringify(votes));}catch{}}
let reportCache=[];
function reportUrlKey(value){
  try{
    const url=new URL(/^https?:\/\//i.test(String(value).trim())?String(value).trim():`https://${String(value).trim()}`),ignored=new Set(['fbclid','gclid','dclid','msclkid']);
    url.hash='';for(const key of [...url.searchParams.keys()])if(key.toLowerCase().startsWith('utm_')||ignored.has(key.toLowerCase()))url.searchParams.delete(key);
    url.searchParams.sort();let path=url.pathname.replace(/\/{2,}/g,'/').replace(/\/+$/,'')||'/';try{path=decodeURIComponent(path);}catch{}
    return`${url.hostname.toLowerCase().replace(/^www\./,'')}${path.toLowerCase()}${url.search}`;
  }catch{return'';}
}
let tickerFrame=0,tickerLastTime=0,tickerDirection=1,tickerPaused=false,tickerEdgeDirection=0;
function tickerCycleWidth(){
  const track=$('#report-track'),first=track?.children[0],duplicate=track?.children[reportCache.length];
  return first&&duplicate?duplicate.offsetLeft-first.offsetLeft:0;
}
function normalizeTickerPosition(){
  const ticker=$('#report-ticker'),cycle=tickerCycleWidth();
  if(!ticker||!cycle||reportCache.length<2)return;
  if(ticker.scrollLeft>=cycle)ticker.scrollLeft-=cycle;
}
function animateTicker(time){
  const ticker=$('#report-ticker');
  if(!tickerLastTime)tickerLastTime=time;
  const elapsed=Math.min(40,time-tickerLastTime);tickerLastTime=time;
  if(ticker&&reportCache.length>1&&!tickerPaused){
    const direction=tickerEdgeDirection||tickerDirection;
    if(direction<0&&ticker.scrollLeft<=1)ticker.scrollLeft=tickerCycleWidth();
    ticker.scrollLeft+=direction*(tickerEdgeDirection?0.18:0.07)*elapsed;
    normalizeTickerPosition();
  }
  tickerFrame=requestAnimationFrame(animateTicker);
}
function moveTicker(direction){
  const ticker=$('#report-ticker');if(!ticker)return;
  if(direction<0&&ticker.scrollLeft<=1)ticker.scrollLeft=tickerCycleWidth();
  tickerDirection=direction;ticker.scrollBy({left:direction*Math.min(360,ticker.clientWidth*.82),behavior:'smooth'});
  setTimeout(normalizeTickerPosition,500);
}
function startTicker(){if(!tickerFrame)tickerFrame=requestAnimationFrame(animateTicker);}
function formatReportDate(value){
  if(!value)return'Fecha no disponible';
  const date=new Date(String(value).includes('T')?value:String(value).replace(' ','T')+'Z');
  if(Number.isNaN(date.getTime()))return'Fecha no disponible';
  return new Intl.DateTimeFormat('es-DO',{dateStyle:'medium',timeStyle:'short',timeZone:'America/Santo_Domingo'}).format(date);
}
function reportCard(report){
  const voted=!!votedReports()[report.id],label=categoryLabels[report.category]||categoryLabels.otro,date=formatReportDate(report.created_at);
  return `<article class="report-card" data-report-id="${safe(report.id)}"><div class="report-card-head"><span>${safe(label)}</span><span>${safe(String(report.report_count))} reporte(s)</span></div><h3 title="${safe(report.hostname)}">${safe(report.hostname)}</h3><p>${safe(report.notes||'Reporte comunitario pendiente de revisión.')}</p><div class="report-date">🕒 Reportada: ${safe(date)}</div><div class="report-score"><div><strong>${safe(String(report.alert_percentage))}%</strong><small> alerta comunitaria</small></div><div class="vote-buttons"><button type="button" data-vote="alert" title="También me parece sospechosa" ${voted?'disabled':''}>⚠ Sí</button><button type="button" data-vote="dispute" title="No estoy de acuerdo" ${voted?'disabled':''}>✓ No</button></div></div><button class="view-report" type="button" data-view-report><span aria-hidden="true">👁</span> Ver informe</button></article>`;
}
async function loadReports(){
  try{
    const response=await fetch('/api/reports'),data=await response.json(),reports=data.reports||[];
    reportCache=reports;
    const cards=reports.map(reportCard).join('');
    $('#report-track').innerHTML=cards+(reports.length>1?cards:'');
    $('#ticker-prev').hidden=reports.length<2;$('#ticker-next').hidden=reports.length<2;
    requestAnimationFrame(()=>{$('#report-ticker').scrollLeft=0;startTicker();});
  }catch{$('#report-track').innerHTML='<div class="report-loading">No se pudieron cargar los reportes recientes.</div>';}
}
async function openCommunityReport(report){
  const dialog=$('#report-dialog'),body=$('#report-dialog-body'),label=categoryLabels[report.category]||categoryLabels.otro;
  $('#report-dialog-title').textContent=report.hostname;
  body.innerHTML=`<div class="dialog-summary"><div class="dialog-stat"><small>Tipo de alerta</small><b>${safe(label)}</b></div><div class="dialog-stat"><small>Alerta comunitaria</small><b>${safe(String(report.alert_percentage))}%</b></div><div class="dialog-stat"><small>Fecha y hora reportada</small><b>${safe(formatReportDate(report.created_at))}</b></div><div class="dialog-stat"><small>Participación</small><b>${safe(String(report.report_count))} reporte(s) · ${safe(String(report.total_opinions))} opinión(es)</b></div></div><div class="dialog-url">${safe(report.canonical_url)}</div><p class="dialog-note">${safe(report.notes||'Sin descripción adicional.')}</p><div class="dialog-analysis"><h3>Análisis técnico actualizado</h3><div class="dialog-loading">Analizando la dirección reportada…</div></div>`;
  dialog.showModal();
  try{
    const target=normalize(report.canonical_url),base=baseSignals(target);
    const[tech,deep]=await Promise.all([technicalChecks(base.host),deepChecks(target)]);
    const score=Math.min(100,base.score+tech.score+deep.score),findings=[...base.findings,...tech.findings,...deep.findings],checks=[...base.checks,...tech.checks,...deep.checks],details=[...base.details,...tech.details,...deep.details];
    const level=score>=60?'RIESGO ALTO':score>=30?'PRECAUCIÓN':'SIN ALERTAS TÉCNICAS EVIDENTES';
    body.querySelector('.dialog-analysis').innerHTML=`<h3>Análisis técnico actualizado</h3><div class="dialog-summary"><div class="dialog-stat"><small>Puntuación técnica</small><b>${score}/100</b></div><div class="dialog-stat"><small>Veredicto orientativo</small><b>${safe(level)}</b></div><div class="dialog-stat"><small>Datos encontrados</small><b>${details.length}</b></div></div><div class="analysis-meta">${checks.map(([name,value,state])=>`<div class="meta-card ${state}"><small>${safe(name)}</small><b>${safe(value)}</b></div>`).join('')}</div><div class="dialog-findings">${(findings.length?findings:['No se encontraron señales adicionales.']).map(item=>`<div class="dialog-finding">${safe(item)}</div>`).join('')}</div><details class="detail-panel"><summary class="detail-heading"><div><p class="eyebrow">EVIDENCIA TÉCNICA</p><h3>Ver todos los datos</h3></div><span><b>${details.length} datos</b><i>Ver detalles</i></span></summary><div class="detail-list">${details.map(([name,value])=>`<div class="detail-row"><span>${safe(name)}</span><b>${safe(value||'No disponible')}</b></div>`).join('')}</div></details>`;
  }catch(error){body.querySelector('.dialog-analysis').innerHTML=`<h3>Análisis técnico actualizado</h3><div class="dialog-finding">No se pudo actualizar el análisis: ${safe(error.message||'error desconocido')}.</div>`;}
}
$('#report-track').addEventListener('click',async event=>{
  const card=event.target.closest('[data-report-id]');if(!card)return;
  if(event.target.closest('[data-view-report]')){const report=reportCache.find(item=>item.id===card.dataset.reportId);if(report)await openCommunityReport(report);return;}
  const button=event.target.closest('[data-vote]');if(!button||button.disabled)return;
  card.querySelectorAll('button').forEach(item=>item.disabled=true);
  try{
    const response=await fetch(`/api/reports/${encodeURIComponent(card.dataset.reportId)}/vote`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({vote:button.dataset.vote})});
    if(!response.ok)throw new Error();rememberVote(card.dataset.reportId);await loadReports();
  }catch{card.querySelectorAll('button').forEach(item=>item.disabled=false);}
});
function focusReportCard(button,active){
  const card=button?.closest('.report-card');if(!card)return;
  card.classList.toggle('is-report-focused',active);
  tickerPaused=active;
}
$('#report-track').addEventListener('pointerover',event=>{
  const button=event.target.closest('[data-view-report]');if(button)focusReportCard(button,true);
});
$('#report-track').addEventListener('pointerout',event=>{
  const button=event.target.closest('[data-view-report]');if(!button||button.contains(event.relatedTarget))return;
  focusReportCard(button,false);
});
$('#report-track').addEventListener('focusin',event=>{
  const button=event.target.closest('[data-view-report]');if(button)focusReportCard(button,true);
});
$('#report-track').addEventListener('focusout',event=>{
  const button=event.target.closest('[data-view-report]');if(!button||button.contains(event.relatedTarget))return;
  focusReportCard(button,false);
});
const previousControl=$('#ticker-prev'),nextControl=$('#ticker-next');
previousControl.addEventListener('click',()=>moveTicker(-1));
nextControl.addEventListener('click',()=>moveTicker(1));
previousControl.addEventListener('pointerenter',()=>{tickerEdgeDirection=-1;tickerPaused=false;});
nextControl.addEventListener('pointerenter',()=>{tickerEdgeDirection=1;tickerPaused=false;});
[previousControl,nextControl].forEach(control=>control.addEventListener('pointerleave',()=>{tickerEdgeDirection=0;tickerPaused=false;}));
$('#report-ticker').addEventListener('mouseenter',()=>{tickerPaused=false;});
$('#report-ticker').addEventListener('keydown',event=>{if(event.key==='ArrowLeft'){event.preventDefault();moveTicker(-1);}if(event.key==='ArrowRight'){event.preventDefault();moveTicker(1);}});
$('#report-ticker').addEventListener('touchstart',()=>{tickerPaused=true;},{passive:true});
$('#report-ticker').addEventListener('touchend',()=>{tickerPaused=false;setTimeout(normalizeTickerPosition,350);},{passive:true});
$('#close-report-dialog').addEventListener('click',()=>$('#report-dialog').close());
$('#report-dialog').addEventListener('click',event=>{if(event.target===$('#report-dialog'))$('#report-dialog').close();});
$('#show-report-form').addEventListener('click',()=>{
  if(existingAnalyzedReport)return;
  const reportForm=$('#report-form');reportForm.hidden=!reportForm.hidden;
  if(!reportForm.hidden){const current=$('#target').value.trim();if(current&&!$('#report-url').value)$('#report-url').value=/^https?:\/\//i.test(current)?current:`https://${current}`;$('#report-url').focus();}
});
$('#view-existing-report').addEventListener('click',()=>{if(existingAnalyzedReport)openCommunityReport(existingAnalyzedReport);});
$('#report-form').addEventListener('submit',async event=>{
  event.preventDefault();const message=$('#report-message'),submit=event.currentTarget.querySelector('button[type="submit"]');submit.disabled=true;message.className='report-message';message.textContent='Comprobando y guardando reporte…';
  try{
    const submittedKey=reportUrlKey($('#report-url').value),known=reportCache.find(report=>reportUrlKey(report.canonical_url)===submittedKey);
    if(known){
      message.className='report-message duplicate';message.innerHTML='<span>⚠ Esta URL ya fue reportada. No se creó un reporte duplicado.</span><button type="button" class="existing-report-button">👁 Ver informe existente</button>';
      message.querySelector('button').addEventListener('click',()=>openCommunityReport(known),{once:true});return;
    }
    const response=await fetch('/api/reports',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({url:$('#report-url').value,category:$('#report-category').value,notes:$('#report-notes').value})}),data=await response.json();
    if(!response.ok)throw new Error(data.error||'No se pudo guardar.');
    if(data.duplicate){
      updateReportAction(data.report);
      message.className='report-message duplicate';
      message.innerHTML='<span>⚠ Esta URL ya fue reportada. No se creó un reporte duplicado.</span><button type="button" class="existing-report-button">👁 Ver informe existente</button>';
      message.querySelector('button').addEventListener('click',()=>openCommunityReport(data.report),{once:true});
    }else{
      updateReportAction(data.report);message.textContent='Reporte recibido. Gracias por alertar a la comunidad.';event.currentTarget.reset();await loadReports();
    }
  }catch(error){message.className='report-message duplicate';message.textContent=error.message||'No se pudo guardar el reporte.';}
  finally{submit.disabled=false;}
});
loadReports();

let deferredInstallPrompt=null;
const installButton=$('#install-app');
window.addEventListener('beforeinstallprompt',event=>{
  event.preventDefault();
  deferredInstallPrompt=event;
  installButton?.classList.add('is-ready');
});
installButton?.addEventListener('click',async()=>{
  if(deferredInstallPrompt){
    deferredInstallPrompt.prompt();
    await deferredInstallPrompt.userChoice;
    deferredInstallPrompt=null;
    installButton.classList.remove('is-ready');
    return;
  }
  alert('Para instalar AlertaURL OSINT, abre el menú de tu navegador y selecciona “Instalar aplicación” o “Añadir a pantalla de inicio”.');
});
window.addEventListener('appinstalled',()=>{
  deferredInstallPrompt=null;
  if(installButton)installButton.textContent='✓ App instalada';
});
if('serviceWorker' in navigator){
  window.addEventListener('load',()=>navigator.serviceWorker.register('/sw.js').catch(()=>{}));
}
