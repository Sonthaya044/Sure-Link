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
    const analyticsLink = document.querySelector('#analyticsSection a[href*="history"]');
    if (analyticsLink) analyticsLink.href = '/insights';
    startDemoUrlTyping();
    loadAnalytics();
});

    const insightsLink = document.querySelector('#analyticsSection a[href*="history"]');
    if (insightsLink) {
        insightsLink.href = '/insights';
        insightsLink.firstChild.textContent = 'ดูสถิติทั้งหมด ';
    }
function startDemoUrlTyping() {
    const demoUrl = document.getElementById('demoUrl');
    if (!demoUrl) return;

    const websites = [
        { url: 'https://google.com/search', risk: 'low', label: 'ปลอดภัย', text: 'ความเสี่ยงต่ำ', threat: 'ไม่พบภัยคุกคาม', score: '18%' },
        { url: 'https://github.com/login', risk: 'low', label: 'ปลอดภัย', text: 'ความเสี่ยงต่ำ', threat: 'ไม่พบภัยคุกคาม', score: '12%' },
        { url: 'https://youtube.com/watch', risk: 'low', label: 'ปลอดภัย', text: 'ความเสี่ยงต่ำ', threat: 'ไม่พบภัยคุกคาม', score: '16%' },
        { url: 'https://wikipedia.org/wiki', risk: 'low', label: 'ปลอดภัย', text: 'ความเสี่ยงต่ำ', threat: 'ไม่พบภัยคุกคาม', score: '9%' },
        { url: 'https://microsoft.com/account', risk: 'medium', label: 'ควรระวัง', text: 'ความเสี่ยงปานกลาง', threat: 'โดเมนใหม่ / Suspicious', score: '54%' },
        { url: 'https://amazon.com/orders', risk: 'low', label: 'ปลอดภัย', text: 'ความเสี่ยงต่ำ', threat: 'ไม่พบภัยคุกคาม', score: '21%' },
        { url: 'https://linkedin.com/feed', risk: 'low', label: 'ปลอดภัย', text: 'ความเสี่ยงต่ำ', threat: 'ไม่พบภัยคุกคาม', score: '14%' },
        { url: 'https://netflix.com/browse', risk: 'medium', label: 'ควรระวัง', text: 'ความเสี่ยงปานกลาง', threat: 'อาจเป็น Phishing', score: '67%' },
        { url: 'https://stackoverflow.com/questions', risk: 'low', label: 'ปลอดภัย', text: 'ความเสี่ยงต่ำ', threat: 'ไม่พบภัยคุกคาม', score: '11%' },
        { url: 'http://secure-account-verify.example', risk: 'high', label: 'อันตราย', text: 'ความเสี่ยงสูง', threat: 'Phishing / ขโมยข้อมูล', score: '94%' }
    ];
    let websiteIndex = 0;
    let characterIndex = 0;
    let deleting = false;

    function tick() {
        const website = websites[websiteIndex];
        demoUrl.textContent = deleting ? website.url.slice(0, characterIndex - 1) : website.url.slice(0, characterIndex + 1);
        characterIndex += deleting ? -1 : 1;

        if (!deleting && characterIndex === website.url.length) {
            updateDemoRisk(website);
            deleting = true;
            setTimeout(tick, 1300);
            return;
        }
        if (deleting && characterIndex === 0) {
            deleting = false;
            websiteIndex = (websiteIndex + 1) % websites.length;
            setTimeout(tick, 300);
            return;
        }
        setTimeout(tick, deleting ? 35 : 70);
    }

    tick();
}

function updateDemoRisk(website) {
    const colors = {
        low: { accent: '#10a37f', icon: 'verified_user', labelClass: 'bg-primary/10 text-primary' },
        medium: { accent: '#ca8a04', icon: 'warning', labelClass: 'bg-warning/10 text-warning' },
        high: { accent: '#dc2626', icon: 'gpp_bad', labelClass: 'bg-error/10 text-error' }
    };
    const style = colors[website.risk];
    const label = document.getElementById('demoRiskLabel');
    const text = document.getElementById('demoRiskText');
    const bar = document.getElementById('demoRiskBar');
    const icon = document.getElementById('demoStatusIcon');
    const threat = document.getElementById('demoThreatType');
    if (!label || !text || !bar || !icon || !threat) return;
    label.className = `rounded-full px-3 py-1 text-xs font-semibold ${style.labelClass}`;
    label.textContent = website.label;
    text.style.color = style.accent;
    text.textContent = website.text;
    bar.style.backgroundColor = style.accent;
    bar.style.width = website.score;
    icon.textContent = style.icon;
    icon.style.color = style.accent;
    icon.style.backgroundColor = `${style.accent}1a`;
    threat.textContent = website.threat;
    threat.style.color = style.accent;
}

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
    const showPercent = Boolean(document.getElementById('analyticsPage'));
    const emptyColor = document.documentElement.classList.contains('dark') ? 'rgba(148,163,184,0.1)' : 'rgba(203,213,225,0.4)';

    threats.forEach((item, idx) => {
        const wrap = document.createElement('div');
        wrap.className = 'flex flex-col items-center bg-surface-container-highest/20 p-4 rounded-2xl w-full border border-outline/20 shadow-sm';
        const cid = `threatChart_${idx}`;
        const displayValue = showPercent ? `${Math.round((item.count / total) * 100)}%` : item.count;
        wrap.innerHTML = `<div class="relative w-20 h-20 sm:w-24 sm:h-24 mb-3"><canvas id="${cid}"></canvas><div class="absolute inset-0 flex items-center justify-center font-bold text-lg sm:text-xl">${displayValue}</div></div><p class="font-semibold text-xs sm:text-sm truncate w-full text-center">${item.threat}</p>`;
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
        options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { ticks: { color: isDark?'#ffffff':'#111827' }, grid: { color: isDark?'rgba(248,250,252,.12)':'rgba(17,24,39,.12)' } }, y: { ticks: { color: isDark?'#ffffff':'#111827' }, grid: { display: false } } } }
    });
}

function renderSiteChart(sites) {
    const canvas = document.getElementById('topSitesChart'); if (!canvas) return;
    if (siteChart) siteChart.destroy();
    const isDark = document.documentElement.classList.contains('dark');
    siteChart = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: { labels: sites.map(s => s.url.substring(0,25)), datasets: [{ data: sites.map(s => s.scanned_count), backgroundColor: '#14b8a6', borderRadius: 6 }] },
        options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { ticks: { color: isDark?'#ffffff':'#111827' }, grid: { color: isDark?'rgba(248,250,252,.12)':'rgba(17,24,39,.12)' } }, y: { ticks: { color: isDark?'#ffffff':'#111827' }, grid: { display: false } } } }
    });
}