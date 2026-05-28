// Enterprise Scanner App Logic

let chartInst = null;
const historyData = [];

// ─── Utility ────────────────────────────────────────────────────────────────
const delay = ms => new Promise(res => setTimeout(res, ms));

// ─── System Health ──────────────────────────────────────────────────────────
async function checkHealth() {
  const dot = document.querySelector('.status-indicator');
  const txt = document.querySelector('.status-text');
  if (!dot) return;
  
  try {
    const res = await fetch('/health');
    if (res.ok) {
      dot.style.backgroundColor = 'var(--status-safe)';
      txt.textContent = 'System Active';
    } else {
      dot.style.backgroundColor = 'var(--status-danger)';
      txt.textContent = 'System Degraded';
    }
  } catch (e) {
    dot.style.backgroundColor = 'var(--status-danger)';
    txt.textContent = 'System Offline';
  }
}

// ─── Scanner Flow ───────────────────────────────────────────────────────────
function initScanner() {
  const urlInput = document.getElementById('url-input');
  if (!urlInput) return;

  const wrapper = document.getElementById('input-wrapper');
  const scanState = document.getElementById('scan-state');
  let scanTimeout = null;

  // Auto-scan on input
  urlInput.addEventListener('input', (e) => {
    clearTimeout(scanTimeout);
    const url = e.target.value.trim();
    
    if (!url) {
      document.getElementById('scanner-results').classList.add('hidden');
      wrapper.classList.remove('scanning');
      scanState.classList.add('hidden');
      return;
    }
    
    // UI Feedback for "ready to scan"
    wrapper.classList.add('scanning');
    scanState.classList.remove('hidden');
    scanState.querySelector('.state-text').textContent = 'Scanning...';
    scanState.querySelector('.spinner').style.display = 'block';
    
    // Debounce the scan
    scanTimeout = setTimeout(() => {
      executeScan(url);
    }, 800);
  });
  
  loadHistory();
}

async function executeScan(url) {
  const wrapper = document.getElementById('input-wrapper');
  const scanState = document.getElementById('scan-state');
  
  try {
    const res = await fetch('/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    
    if (!res.ok) throw new Error('API Error');
    const data = await res.json();
    
    // UI success feedback
    wrapper.classList.remove('scanning');
    scanState.classList.add('hidden');
    
    renderResults(data);
    updateHistory(data);
    
  } catch (err) {
    console.error(err);
    // UI error feedback
    wrapper.classList.remove('scanning');
    scanState.querySelector('.spinner').style.display = 'none';
    scanState.querySelector('.state-text').textContent = 'Scan Failed (Timeout)';
    scanState.style.color = 'var(--status-danger)';
  }
}

function renderResults(data) {
  const container = document.getElementById('scanner-results');
  container.classList.remove('hidden');
  
  const card = document.getElementById('verdict-card');
  const icon = document.getElementById('verdict-icon');
  const title = document.getElementById('verdict-title');
  const urlEl = document.getElementById('verdict-url');
  const conf = document.getElementById('confidence-val');
  
  // Set theme classes
  card.className = `verdict-card ${data.prediction}`;
  
  if (data.prediction === 'benign') {
    title.textContent = 'URL is Safe';
    icon.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>`;
  } else {
    title.textContent = 'Malicious Threat Detected';
    icon.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
  }
  
  urlEl.textContent = data.url;
  conf.textContent = (data.confidence * 100).toFixed(1) + '%';
  
  const rGrid = document.getElementById('reasons-grid');
  rGrid.innerHTML = '';
  
  if (data.top_flags && data.top_flags.length > 0) {
    data.top_flags.forEach(f => {
      rGrid.innerHTML += `
        <div class="reason-card">
          <div class="reason-emoji">${f.icon}</div>
          <div class="reason-text">
            <h4>${f.label}</h4>
            <p>${f.detail}</p>
          </div>
        </div>
      `;
    });
  } else {
    rGrid.innerHTML = `<p style="color: var(--text-muted);">No specific threat indicators were extracted.</p>`;
  }
}

// ─── History Flow ───────────────────────────────────────────────────────────
async function loadHistory() {
  try {
    const res = await fetch('/history');
    if (res.ok) {
      const data = await res.json();
      historyData.length = 0;
      historyData.push(...data);
      renderHistoryTable();
    }
  } catch (e) {}
}

function updateHistory(item) {
  historyData.unshift({
    url: item.url,
    prediction: item.prediction,
    confidence: item.confidence,
    timestamp: item.timestamp
  });
  if (historyData.length > 50) historyData.pop();
  renderHistoryTable();
}

async function clearHistory() {
  historyData.length = 0;
  renderHistoryTable();
  try {
    await fetch('/history', { method: 'DELETE' });
  } catch (e) {}
}

function renderHistoryTable() {
  const tbody = document.getElementById('history-tbody');
  if (!tbody) return;
  
  tbody.innerHTML = '';
  if (historyData.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty-state">No scans recorded yet.</td></tr>`;
    return;
  }
  
  historyData.forEach(h => {
    const date = h.timestamp ? new Date(h.timestamp).toLocaleTimeString() : '--:--';
    const conf = (h.confidence * 100).toFixed(1) + '%';
    tbody.innerHTML += `
      <tr onclick="rescanURL('${h.url}')" title="Click to rescan this URL">
        <td class="mono-text" style="color: var(--text-muted);">${date}</td>
        <td class="mono-text" style="color: var(--text-main); font-weight: 500;">${h.url}</td>
        <td><span class="badge ${h.prediction}">${h.prediction}</span></td>
        <td class="mono-text">${conf}</td>
      </tr>
    `;
  });
}

// Global scope for onclick
window.rescanURL = function(url) {
  const input = document.getElementById('url-input');
  if (input) {
    input.value = url;
    window.scrollTo({ top: 0, behavior: 'smooth' });
    // Trigger input event manually
    input.dispatchEvent(new Event('input'));
  }
};

// ─── Analytics Flow ─────────────────────────────────────────────────────────
function initAnalytics() {
  if (!window.location.pathname.includes('analytics')) return;
  loadModelStats();
}

async function loadModelStats() {
  try {
    const res = await fetch('/stats');
    if (!res.ok) return;
    const data = await res.json();
    


    document.getElementById('metric-accuracy').textContent = (data.accuracy * 100).toFixed(2) + '%';
    document.getElementById('metric-precision').textContent = (data.precision_weighted * 100).toFixed(2) + '%';
    document.getElementById('metric-recall').textContent = (data.recall_weighted * 100).toFixed(2) + '%';
    document.getElementById('metric-f1').textContent = (data.f1_macro * 100).toFixed(2) + '%';
    document.getElementById('metric-auc').textContent = (data.auc_roc * 100).toFixed(2) + '%';
    
    renderChart(data.feature_importance);
  } catch (e) {
    console.error('Failed to load stats', e);
  }
}

function renderChart(importances) {
  if (!importances) return;
  const ctx = document.getElementById('feature-chart');
  if (!ctx || typeof Chart === 'undefined') return;
  
  if (chartInst) chartInst.destroy();
  
  const sorted = Object.entries(importances).sort((a,b) => b[1] - a[1]);
  
  Chart.defaults.font.family = "'Inter', system-ui, sans-serif";
  Chart.defaults.color = '#6b7280';
  
  chartInst = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: sorted.map(i => i[0].replace(/_/g, ' ')),
      datasets: [{
        label: 'Influence Score',
        data: sorted.map(i => i[1]),
        backgroundColor: '#2563eb',
        borderRadius: 4,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: 'y',
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: '#e5e7eb' } },
        y: { grid: { display: false } }
      }
    }
  });
}

// ─── Boot ───────────────────────────────────────────────────────────────────
(async function boot() {
  await checkHealth();
  initScanner();
  initAnalytics();
})();
