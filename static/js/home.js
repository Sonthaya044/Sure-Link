let separateCharts = []; 
let domainChart = null;
let siteChart = null;

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('scanForm');
    if (form) {
        form.addEventListener('submit', () => {
            document.getElementById('btnText').textContent = "กำลังวิเคราะห์...";
            document.getElementById('btnSpinner').classList.remove('hidden');
            document.getElementById('scanBtn').classList.add('opacity-70', 'cursor-wait');
        });
    }
    loadAnalytics();
});

async function loadAnalytics() {
    try {
        const res = await fetch('/analytics');
        const data = await res.json();
        
        // Hide Skeleton and Show Content
        const skeleton = document.getElementById('analyticsSkeleton');
        const content = document.getElementById('analyticsContent');
        if (skeleton) skeleton.classList.add('hidden');
        if (content) {
            content.classList.remove('hidden');
            setTimeout(() => content.classList.add('opacity-100'), 50);
        }
        
        const t = data.tier_counts || {};
        const set = (id, v) => { if(document.getElementById(id)) document.getElementById(id).textContent = (v || 0).toLocaleString(); };
        set('stat-total', data.total_scans); set('stat-high', t.High); set('stat-medium', t.Medium); set('stat-low', t.Low);
        
        renderSeparateThreatCharts(data.top_threats || []); 
        renderDomainChart(data.top_domains || []);
        renderSiteChart(data.top_sites || []);
    } catch (e) { 
        if (document.getElementById('analyticsSkeleton')) document.getElementById('analyticsSkeleton').classList.add('hidden');
        if (document.getElementById('analyticsError')) document.getElementById('analyticsError').classList.remove('hidden'); 
    }
}

function renderSeparateThreatCharts(threats) {
    const container = document.getElementById('threatChartsGrid');
    if (!container) return;
    separateCharts.forEach(c => c.destroy()); separateCharts = []; container.innerHTML = '';

    if (!threats || threats.length === 0) {
        container.innerHTML = '<p class="text-sm text-on-surface-variant py-4 col-span-full flex flex-col items-center"><span class="material-symbols-outlined text-3xl opacity-50 mb-2">data_alert</span> ไม่พบข้อมูลภัยคุกคามในระบบ</p>'; 
        return;
    }
    const total = threats.reduce((s, i) => s + i.count, 0);
    const emptyColor = document.documentElement.classList.contains('dark') ? 'rgba(148,163,184,0.1)' : 'rgba(203,213,225,0.4)';

    threats.forEach((item, idx) => {
        const wrap = document.createElement('div');
        wrap.className = 'flex flex-col items-center bg-surface-container-highest/20 p-4 rounded-2xl w-full border border-outline/20 shadow-sm';
        const cid = `threatChart_${idx}`;
        wrap.innerHTML = `<div class="relative w-20 h-20 sm:w-24 sm:h-24 mb-3"><canvas id="${cid}"></canvas><div class="absolute inset-0 flex items-center justify-center font-bold text-lg sm:text-xl">${item.count}</div></div><p class="font-semibold text-xs sm:text-sm truncate w-full text-center">${item.threat}</p>`;
        container.appendChild(wrap);

        const style = getThreatStyle(item.threat);
        const nc = new Chart(document.getElementById(cid).getContext('2d'), {
            type: 'doughnut', data: { datasets: [{ data: [item.count, total - item.count], backgroundColor: [style.hex, emptyColor], borderWidth: 0 }] },
            options: { responsive: true, maintainAspectRatio: false, cutout: '75%', plugins: { legend: { display: false }, tooltip: { enabled: false } } }
        });
        separateCharts.push(nc);
    });
}

function renderDomainChart(domains) {
    const canvas = document.getElementById('domainChart'); if (!canvas) return;
    if (domainChart) domainChart.destroy();
    const isDark = document.documentElement.classList.contains('dark');
    domainChart = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: { labels: domains.map(d => d.domain.substring(0,25)), datasets: [{ data: domains.map(d => d.count), backgroundColor: '#3b82f6', borderRadius: 6 }] },
        options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { ticks: { color: isDark?'#94a3b8':'#475569' } }, y: { ticks: { color: isDark?'#94a3b8':'#475569' } } } }
    });
}

function renderSiteChart(sites) {
    const canvas = document.getElementById('topSitesChart'); if (!canvas) return;
    if (siteChart) siteChart.destroy();
    const isDark = document.documentElement.classList.contains('dark');
    siteChart = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: { labels: sites.map(s => s.url.substring(0,25)), datasets: [{ data: sites.map(s => s.scanned_count), backgroundColor: '#14b8a6', borderRadius: 6 }] },
        options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { ticks: { color: isDark?'#94a3b8':'#475569' } }, y: { ticks: { color: isDark?'#94a3b8':'#475569' } } } }
    });
}