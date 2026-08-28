let recentScans = [];

async function loadRecentScans() {
    const body = document.getElementById('recentScansBody');
    const filter = document.getElementById('riskFilter');
    if (!body || !filter) return;
    filter.setAttribute('aria-label', 'กรองตามระดับความเสี่ยง');

    try {
        const response = await fetch('/analytics');
        const data = await response.json();
        recentScans = data.recent_scans || [];
        renderRecentScans(filter.value);
        filter.addEventListener('change', () => renderRecentScans(filter.value));
    } catch (error) {
        body.innerHTML = '<tr><td colspan="5" class="p-6 text-center text-error">ไม่สามารถโหลดข้อมูลจากฐานข้อมูลได้</td></tr>';
    }
}

function renderRecentScans(risk) {
    const body = document.getElementById('recentScansBody');
    const rows = recentScans.filter(item => risk === 'all' || item.tier === risk);
    if (rows.length === 0) {
        body.innerHTML = '<tr><td colspan="5" class="p-6 text-center text-on-surface-variant">ยังไม่มีข้อมูลการสแกน</td></tr>';
        return;
    }
    body.innerHTML = rows.map(item => {
        const labels = { High: 'อันตราย', Medium: 'ควรระวัง', Low: 'ปลอดภัย' };
        const colors = { High: 'text-error bg-error/10', Medium: 'text-warning bg-warning/10', Low: 'text-primary bg-primary/10' };
        const scannedAt = item.scanned_timestamp ? new Date(item.scanned_timestamp * 1000).toLocaleString('th-TH') : '-';
        return `<tr class="hover:bg-on-surface/5"><td class="max-w-[28rem] truncate p-3 font-mono text-xs text-primary">${escapeHtml(item.url)}</td><td class="p-3 text-on-surface-variant">${escapeHtml(item.domain || '-')}</td><td class="p-3"><span class="rounded-full px-3 py-1 text-xs font-semibold ${colors[item.tier] || colors.Low}">${labels[item.tier] || item.tier}</span></td><td class="p-3">${item.scan_count || 0}</td><td class="whitespace-nowrap p-3 text-xs text-on-surface-variant">${scannedAt}</td></tr>`;
    }).join('');
}

function escapeHtml(value) {
    return String(value).replace(/[&<>'"]/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[character]));
}

document.addEventListener('DOMContentLoaded', loadRecentScans);
