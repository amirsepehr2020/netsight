import { useMemo, useState } from 'react';
import { Activity, ArrowDown, ArrowUp, Boxes, Cpu, Globe2, LayoutDashboard, ListFilter, Monitor, Network, Radio, Search, Server, Settings2, ShieldCheck, Wifi, X } from 'lucide-react';

type View = 'Overview' | 'Devices' | 'Traffic' | 'Packets' | 'Services';

type Device = { name:string; ip:string; vendor:string; traffic:string; status:'Online'|'Idle'; service:string; color:string };
const devices: Device[] = [
  { name:'SEPEHR-PC', ip:'192.168.1.4', vendor:'Lenovo', traffic:'842 KB', status:'Online', service:'GitHub', color:'#35F2C1' },
  { name:'Galaxy A15', ip:'192.168.1.8', vendor:'Samsung', traffic:'24.8 MB', status:'Online', service:'YouTube', color:'#4EA1FF' },
  { name:'Poco M3', ip:'192.168.1.12', vendor:'Xiaomi', traffic:'8.2 MB', status:'Online', service:'Google', color:'#8D7CFF' },
  { name:'Living Room TV', ip:'192.168.1.19', vendor:'Unknown', traffic:'1.4 MB', status:'Idle', service:'Unknown', color:'#667383' },
];
const services = [
  ['YouTube','2 devices','24.8 MB','96%','DNS + TLS + IP'],
  ['Google','4 devices','8.2 MB','99%','DNS + IP'],
  ['GitHub','1 device','842 KB','94%','DNS + TLS'],
  ['Unknown','3 devices','1.4 MB','—','Insufficient evidence'],
];
const packets = [
  ['21:04:31.221','192.168.1.8','142.250.185.14','TLS','1,480'],
  ['21:04:31.184','192.168.1.8','8.8.8.8','UDP/DNS','92'],
  ['21:04:30.992','192.168.1.4','140.82.112.3','TCP','1,240'],
  ['21:04:30.844','192.168.1.12','142.250.190.14','TLS','1,480'],
  ['21:04:30.702','192.168.1.19','192.168.1.1','UDP','188'],
];

function Sparkline(){ return <div className="sparkline" aria-label="live traffic graph"><span style={{height:'25%'}}/><span style={{height:'42%'}}/><span style={{height:'34%'}}/><span style={{height:'67%'}}/><span style={{height:'54%'}}/><span style={{height:'80%'}}/><span style={{height:'62%'}}/><span style={{height:'91%'}}/><span style={{height:'72%'}}/><span style={{height:'100%'}}/><span style={{height:'79%'}}/><span style={{height:'88%'}}/><span style={{height:'64%'}}/><span style={{height:'73%'}}/><span style={{height:'57%'}}/></div> }

export default function App(){
 const [view,setView]=useState<View>('Overview'); const [expert,setExpert]=useState(false); const [query,setQuery]=useState(''); const [selected,setSelected]=useState<Device|null>(null);
 const filtered=useMemo(()=>devices.filter(d=>(d.name+d.ip+d.vendor+d.service).toLowerCase().includes(query.toLowerCase())),[query]);
 const nav:[View,typeof LayoutDashboard][]=[['Overview',LayoutDashboard],['Devices',Monitor],['Traffic',Activity],['Packets',Radio],['Services',Globe2]];
 return <div className="app">
  <aside className="sidebar">
   <div className="brand"><img src="/assets/brand/logo-mark.svg"/><div><strong>NETSIGHT</strong><small>Know what's moving.</small></div></div>
   <div className="nav">{nav.map(([name,Icon])=><button className={view===name?'active':''} onClick={()=>setView(name)} key={name}><Icon size={18}/><span>{name}</span></button>)}</div>
   <div className="side-bottom"><div className="capture"><span className="live-dot"/><div><b>Capture active</b><small>Wi-Fi · Intel Adapter</small></div></div><button className="settings"><Settings2 size={17}/> Settings</button></div>
  </aside>
  <main className="main">
   <header className="topbar"><div><div className="eyebrow">LOCAL NETWORK / LIVE</div><h1>{view}</h1></div><div className="top-actions"><div className="network-pill"><Wifi size={16}/><span>Wi-Fi</span><i/></div><button className={expert?'mode expert':'mode'} onClick={()=>setExpert(!expert)}>{expert?'Expert':'Easy'} Mode</button></div></header>
   {view==='Overview' && <Overview onSelect={setSelected}/>} 
   {view==='Devices' && <Devices devices={filtered} query={query} setQuery={setQuery} onSelect={setSelected}/>} 
   {view==='Traffic' && <Traffic/>}
   {view==='Packets' && <Packets/>}
   {view==='Services' && <Services/>}
  </main>
  {selected && <div className="drawer-backdrop" onClick={()=>setSelected(null)}><section className="drawer" onClick={e=>e.stopPropagation()}><button className="close" onClick={()=>setSelected(null)}><X size={18}/></button><div className="device-orb"><Monitor size={30}/></div><div className="eyebrow">DEVICE / OBSERVED</div><h2>{selected.name}</h2><p className="muted">{selected.vendor} · {selected.ip}</p><div className="detail-grid"><div><small>STATUS</small><b>{selected.status}</b></div><div><small>TRAFFIC</small><b>{selected.traffic}</b></div><div><small>SERVICE</small><b>{selected.service}</b></div><div><small>CONFIDENCE</small><b>{selected.service==='Unknown'?'—':'96%'}</b></div></div><div className="evidence"><ShieldCheck size={17}/><span>Identity is based on observable network metadata. No HTTPS content is decrypted.</span></div></section></div>}
 </div>
}

function Overview({onSelect}:{onSelect:(d:Device)=>void}){return <div className="content"><section className="hero-card"><div><div className="eyebrow">NETWORK OVERVIEW</div><h2>Everything visible.<br/><em>Nothing guessed.</em></h2><p>NETSIGHT turns observable network activity into a clear, live picture of what's moving.</p></div><div className="hero-orb"><Network size={52}/><span/></div></section><div className="stats"><Stat icon={Boxes} label="Devices" value="12" note="4 active now"/><Stat icon={ArrowDown} label="Download" value="34.4 MB" note="last 5 minutes"/><Stat icon={ArrowUp} label="Upload" value="6.2 MB" note="last 5 minutes"/><Stat icon={Globe2} label="Services" value="23" note="6 identified"/></div><div className="grid-two"><section className="panel traffic-panel"><div className="panel-head"><div><div className="eyebrow">LIVE TRAFFIC</div><h3>Network activity</h3></div><span className="live-badge"><i/> LIVE</span></div><div className="traffic-total"><b>7.82</b><span>MB/s</span></div><Sparkline/><div className="legend"><span><i className="mint"/>Download</span><span><i className="blue"/>Upload</span><span className="muted">Now</span></div></section><section className="panel"><div className="panel-head"><div><div className="eyebrow">TOP SERVICES</div><h3>What's moving</h3></div><button className="text-btn">View all →</button></div><div className="service-mini"><b>YouTube</b><span>24.8 MB</span><strong>96%</strong></div><div className="service-mini"><b>Google</b><span>8.2 MB</span><strong>99%</strong></div><div className="service-mini"><b>GitHub</b><span>842 KB</span><strong>94%</strong></div><div className="service-mini"><b>Unknown</b><span>1.4 MB</span><strong>—</strong></div></section></div><section className="panel"><div className="panel-head"><div><div className="eyebrow">ACTIVE DEVICES</div><h3>Who's online</h3></div><button className="text-btn">All devices →</button></div><div className="device-row head"><span>DEVICE</span><span>IP ADDRESS</span><span>SERVICE</span><span>TRAFFIC</span></div>{devices.slice(0,3).map(d=><div className="device-row" key={d.ip} onClick={()=>onSelect(d)}><span className="device-name"><i style={{background:d.color}}/>{d.name}</span><span className="muted">{d.ip}</span><span><span className="service-tag">{d.service}</span></span><span>{d.traffic}</span></div>)}</section></div>}
function Stat({icon:Icon,label,value,note}:{icon:any,label:string,value:string,note:string}){return <div className="stat"><Icon size={18}/><div><small>{label}</small><b>{value}</b><span>{note}</span></div></div>}
function Devices({devices,query,setQuery,onSelect}:{devices:Device[],query:string,setQuery:(s:string)=>void,onSelect:(d:Device)=>void}){return <div className="content"><div className="toolbar"><div className="search"><Search size={17}/><input value={query} onChange={e=>setQuery(e.target.value)} placeholder="Search devices..."/></div><button className="filter"><ListFilter size={16}/> Filter</button></div><section className="panel"><div className="device-row head"><span>DEVICE</span><span>IP ADDRESS</span><span>VENDOR</span><span>TRAFFIC</span></div>{devices.map(d=><div className="device-row" key={d.ip} onClick={()=>onSelect(d)}><span className="device-name"><i style={{background:d.color}}/><b>{d.name}</b><small>{d.status}</small></span><span className="muted">{d.ip}</span><span>{d.vendor}</span><span>{d.traffic}</span></div>)}{!devices.length&&<div className="empty"><Search size={24}/><b>No devices found</b><span>Try a different search.</span></div>}</section></div>}
function Traffic(){return <div className="content"><section className="panel large-chart"><div className="panel-head"><div><div className="eyebrow">LIVE TRAFFIC</div><h3>Upload / Download</h3></div><span className="live-badge"><i/> LIVE</span></div><div className="big-number">7.82 <small>MB/s</small></div><Sparkline/><div className="traffic-cards"><div><ArrowDown/><small>DOWNLOAD</small><b>6.91 MB/s</b></div><div><ArrowUp/><small>UPLOAD</small><b>0.91 MB/s</b></div></div></section><div className="stats"><Stat icon={Server} label="Active flows" value="38" note="currently observed"/><Stat icon={Activity} label="Packets" value="12.4K" note="last 5 minutes"/><Stat icon={Globe2} label="Domains" value="71" note="DNS observed"/></div></div>}
function Packets(){return <div className="content"><div className="toolbar"><div className="search"><Search size={17}/><input placeholder="Search packets..."/></div><div className="filter-group"><button className="chip active">All</button><button className="chip">TCP</button><button className="chip">UDP</button><button className="chip">DNS</button><button className="chip">TLS</button></div></div><section className="panel packet-panel"><div className="packet-head"><span>TIME</span><span>SOURCE</span><span>DESTINATION</span><span>PROTO</span><span>SIZE</span></div>{packets.map(p=><div className="packet-row" key={p.join('-')}>{p.map((v,i)=><span className={i===3?'proto':''} key={v}>{v}</span>)}</div>)}</section></div>}
function Services(){return <div className="content"><section className="panel"><div className="panel-head"><div><div className="eyebrow">SERVICE DETECTION</div><h3>Recognized services</h3></div><span className="confidence"><ShieldCheck size={15}/> Evidence-based</span></div><div className="service-table head"><span>SERVICE</span><span>DEVICES</span><span>TRAFFIC</span><span>CONFIDENCE</span><span>EVIDENCE</span></div>{services.map(s=><div className="service-table" key={s[0]}><span className="service-name"><i/>{s[0]}</span><span>{s[1]}</span><span>{s[2]}</span><span><b className={s[3]==='—'?'unknown':''}>{s[3]}</b></span><span className="muted">{s[4]}</span></div>)}</section></div>}
