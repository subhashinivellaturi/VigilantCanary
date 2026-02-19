// Minimal interactive behavior for dashboard (vanilla JS)
(() => {
  const toastContainer = document.getElementById('toast-container');
  function toast(text, timeout = 4000) {
    const t = document.createElement('div');
    t.className = 'toast';
    t.textContent = text;
    toastContainer.hidden = false;
    toastContainer.appendChild(t);
    setTimeout(() => { t.remove(); if (!toastContainer.children.length) toastContainer.hidden = true; }, timeout);
  }

  // Sidebar toggle
  const sidebar = document.getElementById('sidebar');
  const toggle = document.getElementById('sidebar-toggle');
  toggle.addEventListener('click', () => sidebar.classList.toggle('open'));

  // Fake data insertion helpers
  function setSeverityCounts(counts) {
    document.querySelectorAll('.severity-card').forEach(card => {
      const key = card.dataset.severity;
      const el = card.querySelector('[data-count]');
      if (counts[key] != null) {
        el.textContent = String(counts[key]);
        el.classList.add('animate');
        setTimeout(()=> el.classList.remove('animate'), 600);
      }
    });
  }

  // Update recent scans table
  function pushScanRow(scan) {
    const tbody = document.getElementById('recent-scans-body');
    const tr = document.createElement('tr');
    tr.innerHTML = `<td><a href="${scan.target}" class="muted">${scan.target}</a></td>
      <td><span class="scan-badge ${scan.type.toLowerCase().replace(/\s+/g,'')}">${scan.type}</span></td>
      <td><span class="status-badge ${scan.status.toLowerCase()}">${scan.status}</span></td>
      <td>${scan.when}</td>
      <td><button class="btn" onclick="(function(){window.location='/reports?scan=${encodeURIComponent(scan.target)}'})()">View Report</button></td>`;
    tbody.prepend(tr);
  }

  // Port scan simulation
  const portForm = document.getElementById('port-form');
  const results = document.getElementById('port-results');
  portForm.addEventListener('submit', e => e.preventDefault());
  document.getElementById('btn-scan').addEventListener('click', () => {
    const target = document.getElementById('port-target').value.trim();
    if (!target) { toast('Enter a target to scan'); return; }
    toast('Port scan started');
    results.innerHTML = '';
    const sample = [{port:80,service:'HTTP',open:true},{port:22,service:'SSH',open:false},{port:443,service:'HTTPS',open:true}];
    sample.forEach((p, i) => {
      const div = document.createElement('div');
      div.className = 'port-result';
      div.innerHTML = `<span class="port-number">:${p.port}</span><span class="port-service">${p.service}</span><span class="port-status ${p.open?'open':'closed'}">${p.open?'Open':'Closed'}</span>`;
      results.appendChild(div);
      setTimeout(()=>{ div.classList.add('found'); }, i*400);
    });
  });

  // Subdomain enumeration (fake)
  document.getElementById('btn-enumerate').addEventListener('click', ()=>{
    const base = document.getElementById('subdomain-input').value.trim();
    if (!base) { toast('Enter a base domain'); return; }
    const container = document.getElementById('subdomain-results');
    container.innerHTML = '';
    ['admin','api','dev','staging'].forEach((s,i)=>{
      const chip = document.createElement('div');
      chip.className='domain-chip';
      chip.innerHTML = `${s}.${base} <span class="domain-status live">LIVE</span> <button class="btn" style="margin-left:8px" aria-label="Copy ${s}.${base}" onclick="(function(t){navigator.clipboard?.writeText(t); alert('copied')})('${s}.${base}')">Copy</button>`;
      container.appendChild(chip);
    });
    toast('Subdomain enumeration finished');
  });

  // Report generator
  document.getElementById('btn-generate').addEventListener('click', ()=>{
    const format = document.getElementById('report-format').value;
    toast(`Generating ${format}…`);
    const preview = document.getElementById('report-preview');
    preview.textContent = `Preparing ${format} report...`;
    setTimeout(()=>{ preview.textContent = `Report ready. Click to download.`; preview.style.cursor='pointer';},1200);
  });

  // Fake risk feed
  function addRisk(r){
    const risks = document.getElementById('risks-list');
    const item = document.createElement('div');
    item.className = `risk-item ${r.severity}`;
    item.tabIndex = 0;
    item.innerHTML = `<div class="risk-severity">${r.severity.toUpperCase()}</div><div class="risk-title">${r.title}</div><div class="risk-target muted">${r.target}</div><div class="risk-time small muted">${r.time}</div>`;
    risks.prepend(item);
  }

  // Security headers & tech tags demo
  function updateAnalysis(headers, tech) {
    const circle = document.querySelector('.score-circle');
    const score = Math.round(headers.score||0);
    circle.dataset.score = score;
    circle.textContent = `${score}%`;
    circle.style.background = `conic-gradient(var(--low) 0deg, var(--medium) ${score/100*360}deg, rgba(255,255,255,0.02) ${score/100*360}deg)`;
    const hl = document.getElementById('header-list'); hl.innerHTML='';
    (headers.items||[]).forEach(h=>{ const s = document.createElement('div'); s.textContent = `${h.present? '✓':'✗'} ${h.name}`; s.className = h.present? 'header-good':'header-bad'; hl.appendChild(s); });
    const tt = document.getElementById('tech-tags'); tt.innerHTML='';
    (tech||[]).forEach(t=>{ const el = document.createElement('span'); el.className='tech-tag'; el.textContent=t; tt.appendChild(el); });
  }

  // Demo / initial content
  setSeverityCounts({critical:2,high:7,medium:31,low:120});
  pushScanRow({target:'https://example.com',type:'XSS Scan',status:'Completed',when:'2 minutes ago'});
  pushScanRow({target:'https://api.example.com',type:'Full Scan',status:'Running',when:'1 minute ago'});
  addRisk({severity:'critical',title:'SQL Injection detected',target:'https://api.example.com/users',time:'10 minutes ago'});
  updateAnalysis({score:85,items:[{name:'HTTPS',present:true},{name:'X-Frame-Options',present:false}]},['Nginx','Python','jQuery 3.6']);

  // refresh button
  document.getElementById('refresh-data').addEventListener('click', ()=>{ toast('Data refreshed'); });

  // expose utilities for debugging
  window.vc = { setSeverityCounts, pushScanRow, addRisk, updateAnalysis, toast };
})();