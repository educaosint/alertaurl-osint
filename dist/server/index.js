const JSON_HEADERS={'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'};
const MAX_REDIRECTS=6;
const MAX_HTML_BYTES=650000;
const INITIAL_REPORT={
  id:'educa-meta-workers-phishing-2026-09',
  canonical_url:'https://curly-snowflake-a703.dehdgjnaxtqmckj.workers.dev/helpcuabdi',
  display_url:'curly-snowflake-a703.dehdgjnaxtqmckj.workers.dev/helpcuabdi',
  hostname:'curly-snowflake-a703.dehdgjnaxtqmckj.workers.dev',
  category:'suplantacion',
  notes:'Página reportada por suplantar visualmente a Meta y solicitar información mediante un formulario.',
  report_count:1,alert_votes:1,dispute_votes:0,status:'community_reported',created_at:'2026-09-18 00:00:00',updated_at:'2026-09-18 00:00:00'
};

function json(data,status=200){return new Response(JSON.stringify(data),{status,headers:JSON_HEADERS});}
function blockedHost(host){
  const h=host.toLowerCase();
  if(h==='localhost'||h.endsWith('.localhost')||h.endsWith('.local')||h.endsWith('.internal'))return true;
  if(/^\d{1,3}(?:\.\d{1,3}){3}$/.test(h)){
    const p=h.split('.').map(Number);
    return p[0]===10||p[0]===127||p[0]===0||(p[0]===169&&p[1]===254)||(p[0]===172&&p[1]>=16&&p[1]<=31)||(p[0]===192&&p[1]===168);
  }
  return h==='::1'||h.startsWith('fc')||h.startsWith('fd')||h.startsWith('fe80:');
}
function validated(raw){
  const url=new URL(raw);
  if(!['http:','https:'].includes(url.protocol))throw new Error('Solo se admiten enlaces HTTP o HTTPS.');
  if(url.username||url.password)throw new Error('No se admiten enlaces con credenciales.');
  if(url.port&&!['80','443'].includes(url.port))throw new Error('El enlace utiliza un puerto no permitido.');
  if(blockedHost(url.hostname))throw new Error('No se permiten direcciones locales o privadas.');
  return url;
}
async function readLimited(response){
  if(!response.body)return'';
  const reader=response.body.getReader();const decoder=new TextDecoder();let size=0,text='';
  while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>MAX_HTML_BYTES){await reader.cancel();break;}text+=decoder.decode(value,{stream:true});}
  return text+decoder.decode();
}
function count(text,re){return(text.match(re)||[]).length;}
function textValue(value){return(value||'').replace(/&(?:amp|#38);/gi,'&').replace(/&(?:quot|#34);/gi,'"').replace(/&#39;|&apos;/gi,"'").replace(/&lt;/gi,'<').replace(/&gt;/gi,'>').replace(/\s+/g,' ').trim().slice(0,300);}
function inspectContent(html,pageUrl){
  const plain=html.replace(/<script[\s\S]*?<\/script>/gi,' ').replace(/<style[\s\S]*?<\/style>/gi,' ').replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').toLowerCase();
  const signals=[],categories=[];let score=0;
  const title=textValue(html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]);
  const description=textValue(html.match(/<meta[^>]+(?:name|property)\s*=\s*["'](?:description|og:description)["'][^>]+content\s*=\s*["']([^"']*)["']/i)?.[1]||html.match(/<meta[^>]+content\s*=\s*["']([^"']*)["'][^>]+(?:name|property)\s*=\s*["'](?:description|og:description)["']/i)?.[1]);
  const forms=count(html,/<form\b/gi);
  const passwordFields=count(html,/<input[^>]+type\s*=\s*["']?password/gi);
  const sensitiveFields=count(html,/<input[^>]+(?:name|autocomplete)\s*=\s*["'][^"']*(?:card|credit|cc-number|otp|one-time-code|password|passcode)[^"']*["']/gi);
  const linkMatches=[...html.matchAll(/<a[^>]+href\s*=\s*["']([^"'#]+)["']/gi)].slice(0,500);
  const pageHost=new URL(pageUrl).hostname.replace(/^www\./,'');
  const externalDomains=new Set();
  for(const match of linkMatches){try{const h=new URL(match[1],pageUrl).hostname.replace(/^www\./,'');if(h&&h!==pageHost)externalDomains.add(h);}catch{}}
  const popups=count(html,/window\.open\s*\(|showModalDialog\s*\(|target\s*=\s*["']_blank["']|on(?:load|click)\s*=\s*["'][^"']*(?:open|popup)/gi);
  const deceptive=count(html,/(?:has ganado|premio exclusivo|descarga ahora|permitir notificaciones|allow notifications|your device is infected|su dispositivo está infectado|click aquí para continuar)/gi);
  if(popups>=2){score+=18;signals.push(`Se encontraron ${popups} instrucciones relacionadas con ventanas nuevas o emergentes.`);}
  else if(popups===1){score+=7;signals.push('La página contiene una instrucción que puede abrir otra ventana.');}
  if(deceptive){score+=18;signals.push('El contenido incluye mensajes asociados con publicidad insistente o engañosa.');}
  const gambling=count(plain,/(?:casino online|apuestas deportivas|casa de apuestas|sportsbook|bet now|bono de bienvenida|tragamonedas|slot machine|ruleta online|poker online)/gi);
  const weapons=count(plain,/(?:armas a la venta|venta de armas|buy firearms|guns for sale|ammo for sale|municiones a la venta|rifles? a la venta|pistolas? a la venta)/gi);
  const drugs=count(plain,/(?:buy cocaine|buy fentanyl|venta de cocaína|comprar cocaína|drogas a domicilio|documentos falsos|fake passports|tarjetas clonadas|stolen credit cards)/gi);
  if(gambling){score+=24;categories.push('Apuestas o casino');signals.push('La página contiene múltiples términos relacionados con apuestas o juegos de azar.');}
  if(weapons){score+=28;categories.push('Venta de armas');signals.push('La página parece ofrecer armas o municiones. Puede tratarse de contenido regulado según el país.');}
  if(drugs){score+=40;categories.push('Posible actividad ilícita');signals.push('El contenido coincide con ofertas comúnmente asociadas con bienes o servicios ilícitos.');}
  const dataFields=count(html,/<input[^>]+type\s*=\s*["']?(?:password|tel|email)/gi);
  if(dataFields&&deceptive){score+=15;signals.push('La página combina solicitudes de datos con mensajes de presión o engaño.');}
  return{score,signals,categories,popups,deceptive,pageInfo:{title,description,forms,passwordFields,sensitiveFields,dataFields,externalLinks:linkMatches.length,externalDomains:[...externalDomains].slice(0,20),htmlBytes:new TextEncoder().encode(html).byteLength}};
}
async function analyze(raw){
  let current=validated(raw),response;const chain=[],hops=[];
  for(let i=0;i<=MAX_REDIRECTS;i++){
    chain.push(current.href);
    const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),8000);
    try{response=await fetch(current.href,{redirect:'manual',signal:controller.signal,headers:{'user-agent':'EducaOSINT-Verifica/1.0','accept':'text/html,application/xhtml+xml'}});}
    finally{clearTimeout(timer);}
    hops.push({url:current.href,status:response.status,location:response.headers.get('location')||null});
    if(response.status>=300&&response.status<400){
      const location=response.headers.get('location');
      if(!location)break;
      if(i===MAX_REDIRECTS)throw new Error('La cadena supera el máximo de redirecciones permitido.');
      current=validated(new URL(location,current).href);continue;
    }
    break;
  }
  const contentType=response?.headers.get('content-type')||'';
  let content={score:0,signals:[],categories:[],popups:0,deceptive:0,pageInfo:{title:'',description:'',forms:0,passwordFields:0,sensitiveFields:0,dataFields:0,externalLinks:0,externalDomains:[],htmlBytes:0}};
  if(response&&contentType.toLowerCase().includes('text/html'))content=inspectContent(await readLimited(response),current.href);
  const domains=[...new Set(chain.map(item=>new URL(item).hostname.replace(/^www\./,'').toLowerCase()))];
  const crossDomain=domains.length>1;
  const signals=[...content.signals];
  let score=content.score;
  if(chain.length>1){signals.unshift(`El enlace realiza ${chain.length-1} redirección(es).`);score+=Math.min(24,(chain.length-1)*7);}
  if(crossDomain){signals.unshift(`La navegación cambia entre ${domains.length} dominios diferentes.`);score+=20;}
  return{...content,score:Math.min(100,score),chain,hops,domains,finalUrl:current.href,status:response?.status||0,contentType,crossDomain,signals};
}

function reportView(row){
  const alerts=Number(row.report_count||0)+Number(row.alert_votes||0),disputes=Number(row.dispute_votes||0),total=alerts+disputes;
  return{...row,alert_percentage:total?Math.round(alerts*100/total):0,total_opinions:total};
}
function cleanReportUrl(raw){
  const url=validated(raw);url.hash='';
  return{canonical:url.href,display:url.href.replace(/^https?:\/\//,''),hostname:url.hostname.toLowerCase(),key:reportUrlKey(url)};
}
function reportUrlKey(value){
  const url=value instanceof URL?new URL(value.href):validated(String(value));
  const ignored=new Set(['fbclid','gclid','dclid','msclkid']);
  for(const key of [...url.searchParams.keys()])if(key.toLowerCase().startsWith('utm_')||ignored.has(key.toLowerCase()))url.searchParams.delete(key);
  url.searchParams.sort();
  let path=url.pathname.replace(/\/{2,}/g,'/').replace(/\/+$/,'')||'/';
  try{path=decodeURIComponent(path);}catch{}
  return`${url.hostname.toLowerCase().replace(/^www\./,'')}${path.toLowerCase()}${url.search}`;
}
async function listReports(db){
  const result=await db.prepare(`SELECT id, canonical_url, display_url, hostname, category, notes, report_count, alert_votes, dispute_votes, status, created_at, updated_at
    FROM reported_sites ORDER BY updated_at DESC LIMIT 14`).all();
  const rows=result.results||[];
  if(!rows.some(row=>row.id===INITIAL_REPORT.id))rows.push(INITIAL_REPORT);
  return rows.sort((a,b)=>String(b.updated_at||'').localeCompare(String(a.updated_at||''))).slice(0,14).map(reportView);
}
async function findExistingReport(db,parsed){
  if(parsed.key===reportUrlKey(INITIAL_REPORT.canonical_url))return reportView(INITIAL_REPORT);
  const baseHost=parsed.hostname.replace(/^www\./,'');
  const candidates=await db.prepare(`SELECT id, canonical_url, display_url, hostname, category, notes, report_count, alert_votes, dispute_votes, status, created_at, updated_at
    FROM reported_sites WHERE LOWER(hostname) IN (LOWER(?), LOWER(?))`).bind(baseHost,`www.${baseHost}`).all();
  const existing=(candidates.results||[]).find(row=>{try{return reportUrlKey(row.canonical_url)===parsed.key;}catch{return false;}});
  return existing?reportView(existing):null;
}
async function saveReport(db,body){
  const parsed=cleanReportUrl(String(body?.url||''));
  const existing=await findExistingReport(db,parsed);
  if(existing)return{report:existing,duplicate:true};
  const allowed=new Set(['suplantacion','phishing','estafa','apuestas','armas','contenido_ilicito','publicidad_enganosa','otro']);
  const category=allowed.has(body?.category)?body.category:'otro';
  const notes=String(body?.notes||'').replace(/[<>]/g,'').trim().slice(0,500);
  const id=crypto.randomUUID();
  await db.prepare(`INSERT INTO reported_sites
    (id, canonical_url, display_url, hostname, category, notes, report_count, alert_votes, dispute_votes, status, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, 1, 0, 0, 'community_reported', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    ON CONFLICT(canonical_url) DO NOTHING`)
    .bind(id,parsed.canonical,parsed.display,parsed.hostname,category,notes).run();
  const row=await db.prepare(`SELECT id, canonical_url, display_url, hostname, category, notes, report_count, alert_votes, dispute_votes, status, created_at, updated_at
    FROM reported_sites WHERE canonical_url = ?`).bind(parsed.canonical).first();
  return{report:reportView(row),duplicate:row?.id!==id};
}
async function voteReport(db,id,vote){
  if(id===INITIAL_REPORT.id){
    await db.prepare(`INSERT INTO reported_sites
      (id, canonical_url, display_url, hostname, category, notes, report_count, alert_votes, dispute_votes, status, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, 1, 1, 0, 'community_reported', ?, ?)
      ON CONFLICT(canonical_url) DO NOTHING`).bind(INITIAL_REPORT.id,INITIAL_REPORT.canonical_url,INITIAL_REPORT.display_url,INITIAL_REPORT.hostname,INITIAL_REPORT.category,INITIAL_REPORT.notes,INITIAL_REPORT.created_at,INITIAL_REPORT.updated_at).run();
  }
  const column=vote==='alert'?'alert_votes':vote==='dispute'?'dispute_votes':null;
  if(!column)throw new Error('Valoración inválida.');
  await db.prepare(`UPDATE reported_sites SET ${column} = ${column} + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?`).bind(id).run();
  const row=await db.prepare(`SELECT id, canonical_url, display_url, hostname, category, notes, report_count, alert_votes, dispute_votes, status, created_at, updated_at
    FROM reported_sites WHERE id = ?`).bind(id).first();
  if(!row)throw new Error('Reporte no encontrado.');
  return reportView(row);
}

export default{
  async fetch(request,env){
    const url=new URL(request.url);
    if(url.pathname==='/api/analyze-url'){
      if(request.method!=='POST')return json({error:'Método no permitido.'},405);
      try{
        const body=await request.json();
        if(typeof body?.url!=='string'||body.url.length>2048)return json({error:'Dirección inválida.'},400);
        return json(await analyze(body.url));
      }catch(error){return json({error:error?.message==='The operation was aborted.'?'La página tardó demasiado en responder.':(error?.message||'No se pudo inspeccionar la página.')},422);}
    }
    if(url.pathname==='/api/reports'&&request.method==='GET'){
      try{return json({reports:await listReports(env.DB)});}catch{return json({reports:[reportView(INITIAL_REPORT)],warning:'El registro comunitario no está disponible temporalmente.'});}
    }
    if(url.pathname==='/api/reports/check'&&request.method==='POST'){
      try{
        const body=await request.json();
        if(typeof body?.url!=='string'||body.url.length>2048)return json({error:'Dirección inválida.'},400);
        const report=await findExistingReport(env.DB,cleanReportUrl(body.url));
        return json({reported:!!report,report});
      }catch(error){return json({error:error?.message||'No se pudo comprobar el reporte.'},422);}
    }
    if(url.pathname==='/api/reports'&&request.method==='POST'){
      try{
        const saved=await saveReport(env.DB,await request.json());
        return json(saved,saved.duplicate?200:201);
      }catch(error){return json({error:error?.message||'No se pudo guardar el reporte.'},422);}
    }
    const voteMatch=url.pathname.match(/^\/api\/reports\/([^/]+)\/vote$/);
    if(voteMatch&&request.method==='POST'){
      try{return json({report:await voteReport(env.DB,decodeURIComponent(voteMatch[1]),(await request.json())?.vote)});}catch(error){return json({error:error?.message||'No se pudo guardar la valoración.'},422);}
    }
    if(env?.ASSETS)return env.ASSETS.fetch(request);
    return new Response('Not found',{status:404});
  }
};
