let myChart = null;
let lastThreatData = null;
let currentThreatFilter = null;

document.addEventListener('DOMContentLoaded', () => {
    const rawData = document.getElementById('scan-data').textContent;
    const data = JSON.parse(rawData);
    updateDashboardUI(data);
    saveToHistory(data); // 🟢 บันทึกเข้าประวัติ
});

window.addEventListener('themeChanged', () => {
    if (lastThreatData) renderThreatChartLocal(lastThreatData);
});

function filterThreatCards(category) {
    currentThreatFilter = category;
    const cards = document.querySelectorAll('.threat-card');
    const badge = document.getElementById('activeFilterBadge');
    const label = document.getElementById('filterLabel');
    const toggleBtn = document.querySelector('#scanLog button');

    if (category) {
        badge.classList.remove('hidden');
        badge.classList.add('flex');
        label.textContent = category;
        if (toggleBtn) toggleBtn.parentElement.classList.add('hidden');
        
        cards.forEach(card => {
            if (card.getAttribute('data-category') === category) {
                card.classList.remove('hidden', 'scale-95', 'opacity-0');
                card.classList.add('flex', 'scale-100', 'opacity-100');
            } else {
                card.classList.add('hidden');
                card.classList.remove('flex', 'scale-100', 'opacity-100');
            }
        });
    } else {
        badge.classList.add('hidden');
        badge.classList.remove('flex');
        if (toggleBtn) toggleBtn.parentElement.classList.remove('hidden');
        
        const MAX_VISIBLE = 8;
        const isExpanded = toggleBtn && toggleBtn.dataset.expanded === 'true';
        
        cards.forEach((card, index) => {
            if (index < MAX_VISIBLE || isExpanded) {
                card.classList.remove('hidden');
                card.classList.add('flex', 'scale-100', 'opacity-100');
            } else {
                card.classList.add('hidden');
                card.classList.remove('flex', 'scale-100', 'opacity-100');
            }
        });
    }
}

function clearThreatFilter() {
    filterThreatCards(null);
}

function extractPrimaryThreatType(data) {
    if (!data || data.tier === 'Low') return 'ปลอดภัย';
    const engineResults = Object.values(data.engine_results || {});
    const counts = {};
    engineResults.forEach(res => {
        if (res && res.category && (res.category === 'malicious' || res.category === 'suspicious')) {
            const style = getThreatStyle(res.result, res.category);
            let key = 'Malicious';
            if (style.hex === '#f97316') key = 'Phishing';
            else if (style.hex === '#ef4444') key = 'Malware';
            else if (style.hex === '#eab308') key = 'Suspicious';
            counts[key] = (counts[key] || 0) + 1;
        }
    });
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    return sorted.length > 0 ? sorted[0][0] : 'ภัยคุกคาม';
}

function countDetectedThreats(engineResults) {
    if (!engineResults || typeof engineResults !== 'object') return 0;
    return Object.values(engineResults).filter(result => result && result.category && (result.category === 'malicious' || result.category === 'suspicious')).length;
}

function saveToHistory(data) {
    let history = JSON.parse(localStorage.getItem('scanHistory') || '[]');
    // เช็คว่าลิงก์นี้เพิ่งสแกนซ้ำหรือเปล่า เพื่อไม่ให้ข้อมูลรกเกินไป
    if (history.length > 0 && history[0].url === data.url) return;
    
    let parsedUrl; try { parsedUrl = new URL(data.url); } catch (e) { parsedUrl = null; }
    const threatCount = countDetectedThreats(data.engine_results) || data.malicious || 0;
    
    history.unshift({ 
        time: new Date().toLocaleString(), url: data.url, domain: data.domain || "N/A",
        tier: data.tier, malicious: threatCount, 
        protocol: parsedUrl?.protocol.replace(':','').toUpperCase() || "HTTP", port: parsedUrl?.port || (data.url.startsWith('https')?'443':'80'),
        primaryThreat: extractPrimaryThreatType(data)
    });
    if (history.length > 50) history.pop();
    localStorage.setItem('scanHistory', JSON.stringify(history));
}

function updateDashboardUI(data) {
    const pThreat = extractPrimaryThreatType(data);
    const statusBadge = document.getElementById('statusBadge');
    const statusIcon = document.getElementById('statusIcon');
    const riskStatus = document.getElementById('riskStatus');
    const malCountEl = document.getElementById('maliciousCount');
    const mitigationSection = document.getElementById('mitigationSection');
    const mitigationIcon = document.getElementById('mitigationIcon');
    const mitigationTitle = document.getElementById('mitigationTitle');
    const mitigationContent = document.getElementById('mitigationContent');
    const fullLogSection = document.getElementById('fullLogSection');
    const chartContainer = document.getElementById('chartContainer');
    const noThreatMessage = document.getElementById('noThreatMessage');

    let parsedUrl;
    try { parsedUrl = new URL(data.url); } catch (e) { parsedUrl = null; }
    document.getElementById('httpProtocol').textContent = parsedUrl ? parsedUrl.protocol.replace(':', '').toUpperCase() : (data.url.startsWith('https') ? 'HTTPS' : 'HTTP');
    document.getElementById('httpPort').textContent = parsedUrl ? (parsedUrl.port || (parsedUrl.protocol === 'https:' ? '443' : '80')) : (data.url.startsWith('https') ? '443' : '80');
    const threatCount = countDetectedThreats(data.engine_results) || data.malicious || 0;
    malCountEl.textContent = threatCount;

    statusBadge.className = "inline-flex w-fit items-center gap-3 px-6 py-4 rounded-full shadow-xl font-bold tracking-[0.1em] transition-all";
    mitigationSection.classList.remove('hidden');

    if (data.tier === 'High') {
        statusBadge.classList.add('bg-error', 'text-white');
        statusIcon.textContent = "gpp_bad"; riskStatus.textContent = `High (${pThreat})`;
        malCountEl.className = "mt-1 text-4xl font-bold font-headline leading-none text-error drop-shadow-sm";
        mitigationSection.className = "mt-6 w-full rounded-[2rem] border border-error/40 bg-error/10 p-6 sm:p-8 shadow-lg";
        mitigationIcon.className = "material-symbols-outlined text-error text-3xl shrink-0 filled"; mitigationIcon.textContent = "warning";
        mitigationTitle.className = "text-xl sm:text-2xl font-bold text-error"; mitigationTitle.textContent = "คำแนะนำเบื้องต้น";
        mitigationContent.innerHTML = `<ul class="list-none pl-2 space-y-3 mt-2 text-error/90 font-medium text-sm sm:text-base">
            <li class="flex items-start gap-2"><span class="material-symbols-outlined text-[20px] shrink-0">block</span> <strong>รีบปิดหน้าเว็บนี้ทิ้ง:</strong> เว็บนี้อันตรายมาก อย่ากดทำอะไรเด็ดขาดนะครับ</li>
            <li class="flex items-start gap-2"><span class="material-symbols-outlined text-[20px] shrink-0">delete_sweep</span> <strong>ล้างประวัติการเข้าชม:</strong> เพื่อความปลอดภัย ให้เคลียร์แคชและคุกกี้ที่อาจติดมาด้วยครับ</li>
            <li class="flex items-start gap-2"><span class="material-symbols-outlined text-[20px] shrink-0">security_update</span> <strong>ตรวจสอบเครื่อง:</strong> ถ้าเผลอกดเข้าไปแล้ว แนะนำให้สแกนไวรัสในเครื่องดูอีกสักรอบครับ</li>
        </ul>`;
    } else if (data.tier === 'Medium') {
        statusBadge.classList.add('bg-warning', 'text-white');
        statusIcon.textContent = "warning"; riskStatus.textContent = `Medium (${pThreat})`;
        malCountEl.className = "mt-1 text-4xl font-bold font-headline leading-none text-warning drop-shadow-sm";
        mitigationSection.className = "mt-6 w-full rounded-[2rem] border border-warning/40 bg-warning/10 p-6 sm:p-8 shadow-lg";
        mitigationIcon.className = "material-symbols-outlined text-warning text-3xl shrink-0 filled"; mitigationIcon.textContent = "error_outline";
        mitigationTitle.className = "text-xl sm:text-2xl font-bold text-warning"; mitigationTitle.textContent = "คำแนะนำเบื้องต้น";
        mitigationContent.innerHTML = `<ul class="list-none pl-2 space-y-3 mt-2 text-warning/90 font-medium text-sm sm:text-base">
            <li class="flex items-start gap-2"><span class="material-symbols-outlined text-[20px] shrink-0">warning</span> <strong>Proceed with Caution:</strong> ถ้าไม่จำเป็นก็หลีกเลี่ยงการเข้าเว็บนี้นะครับ</li>
            <li class="flex items-start gap-2"><span class="material-symbols-outlined text-[20px] shrink-0">vpn_key_off</span> <strong>No Credentials:</strong> ห้ามกรอกรหัสผ่านหรือข้อมูลส่วนตัวใดๆ เด็ดขาด</li>
        </ul>`;
    } else {
        statusBadge.classList.add('bg-tertiary', 'text-white', 'dark:text-[#061428]');
        statusIcon.textContent = "verified_user"; riskStatus.textContent = "Low (ปลอดภัย)";
        malCountEl.className = "mt-1 text-4xl font-bold font-headline leading-none text-on-surface drop-shadow-sm";
        mitigationSection.className = "mt-6 w-full rounded-[2rem] border border-tertiary/40 bg-tertiary/10 p-6 sm:p-8 shadow-lg";
        mitigationIcon.className = "material-symbols-outlined text-tertiary text-3xl shrink-0 filled"; mitigationIcon.textContent = "check_circle";
        mitigationTitle.className = "text-xl sm:text-2xl font-bold text-tertiary"; mitigationTitle.textContent = "คำแนะนำและวิธีป้องกัน";
        mitigationContent.innerHTML = `<ul class="list-none pl-2 space-y-3 mt-2 text-tertiary/90 font-medium text-sm sm:text-base">
            <li class="flex items-start gap-2"><span class="material-symbols-outlined text-[20px] shrink-0">check_circle</span> <strong>Safe:</strong> ไม่พบร่องรอยภัยคุกคาม ณ ขณะนี้</li>
        </ul>`;
    }

    if (data.tier === 'High' || data.tier === 'Medium') {
        chartContainer.classList.remove('hidden'); chartContainer.classList.add('flex');
        if(document.getElementById('chartHint')) document.getElementById('chartHint').classList.remove('hidden');
        noThreatMessage.classList.add('hidden');
        fullLogSection.classList.remove('hidden'); fullLogSection.classList.add('flex');

        const logContainer = document.getElementById('scanLog');
        logContainer.innerHTML = '';
        const engineResults = Object.entries(data.engine_results || {});
        lastThreatData = {};
        const threatCards = [];

        engineResults.forEach(([engine, result]) => {
            if (result && result.category && (result.category === 'malicious' || result.category === 'suspicious')) {
                const style = getThreatStyle(result.result, result.category);
                let typeKey = 'Other';
                for (const [key, val] of Object.entries(threatColorMap)) {
                    if (val.hex === style.hex) { typeKey = key.charAt(0).toUpperCase() + key.slice(1); break; }
                }
                if(!lastThreatData[typeKey]) lastThreatData[typeKey] = { count: 0, hex: style.hex };
                lastThreatData[typeKey].count += 1;

                const card = document.createElement('div');
                card.setAttribute('data-category', typeKey);
                card.className = `threat-card h-fit flex flex-col rounded-lg p-3 transition-all duration-500 hover:brightness-95 hover:scale-[1.02] transform animate-in fade-in zoom-in ${style.bg}`;
                card.style.animationDelay = `${threatCards.length * 50}ms`;
                card.innerHTML = `<div class="flex justify-between items-center mb-1"><span class="font-bold text-sm flex items-center gap-2 ${style.text}"><span class="material-symbols-outlined text-[16px]">bug_report</span> <span class="truncate">${engine}</span></span></div><span class="opacity-90 text-xs break-words ${style.text}">${result.result || 'Threat'}</span>`;
                threatCards.push(card);
            }
        });

        const MAX_VISIBLE = 8;
        threatCards.forEach((card, index) => {
            if (index >= MAX_VISIBLE) card.classList.add('hidden', 'extra-threat-card');
            logContainer.appendChild(card);
        });

        if (threatCards.length > MAX_VISIBLE) {
            const toggleBtnContainer = document.createElement('div');
            toggleBtnContainer.className = 'col-span-1 sm:col-span-2 lg:col-span-3 xl:col-span-4 flex justify-center mt-2 pb-2';
            const toggleBtn = document.createElement('button');
            toggleBtn.className = 'flex items-center gap-2 px-6 py-2.5 rounded-full border border-outline/50 bg-surface-container-highest text-sm font-semibold text-on-surface hover:bg-outline/30 transition-all shadow-sm';
            toggleBtn.innerHTML = `ดูเพิ่มเติม (${threatCards.length - MAX_VISIBLE} รายการ) <span class="material-symbols-outlined text-[18px]">expand_more</span>`;
            toggleBtn.onclick = () => {
                const isExpanded = toggleBtn.dataset.expanded === 'true';
                const extraCards = logContainer.querySelectorAll('.extra-threat-card');
                if (isExpanded) {
                    extraCards.forEach(c => c.classList.add('hidden'));
                    toggleBtn.dataset.expanded = 'false';
                    toggleBtn.innerHTML = `ดูเพิ่มเติม (${threatCards.length - MAX_VISIBLE} รายการ) <span class="material-symbols-outlined text-[18px]">expand_more</span>`;
                } else {
                    extraCards.forEach(c => c.classList.remove('hidden'));
                    toggleBtn.dataset.expanded = 'true';
                    toggleBtn.innerHTML = `ย่อเก็บ <span class="material-symbols-outlined text-[18px]">expand_less</span>`;
                }
            };
            toggleBtnContainer.appendChild(toggleBtn);
            logContainer.appendChild(toggleBtnContainer);
        }
        renderThreatChartLocal(lastThreatData);
    } else {
        chartContainer.classList.add('hidden'); chartContainer.classList.remove('flex');
        noThreatMessage.classList.remove('hidden');
    }
}

function renderThreatChartLocal(threatData) {
    const canvas = document.getElementById('riskChart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const labels = Object.keys(threatData);
    const data = labels.map(label => threatData[label].count);
    const bgColors = labels.map(label => threatData[label].hex);
    const isDark = document.documentElement.classList.contains('dark');

    if (myChart) myChart.destroy();
    myChart = new Chart(ctx, {
        type: 'pie',
        data: { labels: labels, datasets: [{ data: data, backgroundColor: bgColors, borderWidth: 0 }] },
        options: { 
            responsive: true, 
            maintainAspectRatio: false,
            animation: {
                animateRotate: true,
                animateScale: true,
                duration: 1200,
                easing: 'easeOutQuart'
            },
            plugins: { 
                legend: { 
                    position: 'right', 
                    labels: { color: isDark ? '#e2e8f0' : '#1e293b', font: { size: 10 } } 
                },
                tooltip: {
                    backgroundColor: isDark ? '#1e293b' : '#ffffff',
                    titleColor: isDark ? '#f8fafc' : '#1e293b',
                    bodyColor: isDark ? '#cbd5e1' : '#475569',
                    borderColor: isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)',
                    borderWidth: 1
                }
            },
            onClick: (event, elements) => {
                if (elements.length > 0) {
                    const index = elements[0].index;
                    const label = labels[index];
                    if (currentThreatFilter === label) {
                        clearThreatFilter();
                    } else {
                        filterThreatCards(label);
                    }
                }
            },
            onHover: (event, elements) => {
                event.native.target.style.cursor = elements.length > 0 ? 'pointer' : 'default';
            }
        }
    });
}