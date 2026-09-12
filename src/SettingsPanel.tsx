import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Settings2, X, ShieldCheck, Radio } from 'lucide-react';

type Settings = { capture_interface: string|null; auto_capture: boolean; privacy_mode: boolean; max_packets: number };
type CaptureInterface = { name: string; description?: string|null };

const fallback: Settings = { capture_interface: null, auto_capture: true, privacy_mode: true, max_packets: 250 };

export default function SettingsPanel(){
  const [open,setOpen]=useState(false); const [settings,setSettings]=useState<Settings>(fallback); const [interfaces,setInterfaces]=useState<CaptureInterface[]>([]); const [busy,setBusy]=useState(false); const [error,setError]=useState('');
  useEffect(()=>{ const onClick=(e:MouseEvent)=>{const el=e.target as HTMLElement|null; if(el?.closest('.settings')) setOpen(true)}; document.addEventListener('click',onClick); return()=>document.removeEventListener('click',onClick); },[]);
  useEffect(()=>{if(!open)return; (async()=>{try{const [s,ifs]=await Promise.all([invoke<Settings>('get_settings'),invoke<CaptureInterface[]>('list_capture_interfaces')]);setSettings(s);setInterfaces(ifs)}catch(e){setError(String(e))}})()},[open]);
  if(!open)return null;
  const save=async()=>{setBusy(true);setError('');try{await invoke('set_settings',{settings});setOpen(false)}catch(e){setError(String(e))}finally{setBusy(false)}};
  const row={display:'flex',justifyContent:'space-between',alignItems:'center',gap:16,padding:'15px 0',borderBottom:'1px solid rgba(255,255,255,.06)'} as const;
  const label={fontSize:11,fontWeight:700,color:'#f5f7fa'} as const; const desc={display:'block',fontSize:8,color:'#687482',marginTop:4,lineHeight:1.5} as const;
  return <div className="drawer-backdrop" onClick={()=>setOpen(false)}><section className="drawer" onClick={e=>e.stopPropagation()} style={{width:460}}><button className="close" onClick={()=>setOpen(false)}><X size={18}/></button><div className="device-orb"><Settings2 size={27}/></div><div className="eyebrow">NETSIGHT / SETTINGS</div><h2>Capture & Privacy</h2><p className="muted">Control what NETSIGHT captures and how much local history it keeps.</p>
    <div style={{marginTop:28}}>
      <div style={row}><div><span style={label}>Capture interface</span><span style={desc}>Select the adapter used for live packet capture.</span></div><select value={settings.capture_interface||''} onChange={e=>setSettings({...settings,capture_interface:e.target.value||null})} style={{maxWidth:205,background:'#111923',color:'#e7edf4',border:'1px solid rgba(255,255,255,.08)',borderRadius:9,padding:'9px 10px',fontSize:9}}><option value="">Auto select</option>{interfaces.map(i=><option key={i.name} value={i.name}>{i.description||i.name}</option>)}</select></div>
      <div style={row}><div><span style={label}>Automatic capture</span><span style={desc}>Start monitoring when NETSIGHT opens.</span></div><input type="checkbox" checked={settings.auto_capture} onChange={e=>setSettings({...settings,auto_capture:e.target.checked})}/></div>
      <div style={row}><div><span style={label}>Privacy mode</span><span style={desc}>Keep encrypted payloads opaque; analyze metadata only.</span></div><input type="checkbox" checked={settings.privacy_mode} onChange={e=>setSettings({...settings,privacy_mode:e.target.checked})}/></div>
      <div style={row}><div><span style={label}>Packet history</span><span style={desc}>Maximum recent packets kept in the current session.</span></div><select value={settings.max_packets} onChange={e=>setSettings({...settings,max_packets:Number(e.target.value)})} style={{background:'#111923',color:'#e7edf4',border:'1px solid rgba(255,255,255,.08)',borderRadius:9,padding:'9px 10px',fontSize:9}}><option value={100}>100</option><option value={250}>250</option><option value={500}>500</option><option value={1000}>1000</option></select></div>
    </div>
    <div className="evidence"><ShieldCheck size={17}/><span>NETSIGHT does not decrypt HTTPS payloads. These settings control observable network metadata and local session storage.</span></div>
    {error&&<div className="notice" style={{margin:'14px 0 0'}}><Radio size={14}/>{error}</div>}
    <div style={{display:'flex',justifyContent:'flex-end',gap:8,marginTop:20}}><button className="filter" onClick={()=>setOpen(false)}>Cancel</button><button className="hero-action" style={{marginTop:0}} disabled={busy} onClick={save}>{busy?'Saving…':'Save settings'}</button></div>
  </section></div>
}
