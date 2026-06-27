document.addEventListener('DOMContentLoaded', () => {
    loadHistoryTable();
});

function loadHistoryTable() {
    const history = JSON.parse(localStorage.getItem('scanHistory') || '[]');
    const tbody = document.querySelector('#historyTable tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (history.length === 0) { 
        const row = document.createElement('tr');
        row.innerHTML = '<td colspan="4" class="p-8 text-center text-on-surface-variant">ยังไม่มีประวัติการสแกน</td>';
        tbody.appendChild(row);
        return; 
    }

    history.forEach((item, index) => {
        let badgeColor = item.tier === 'High' ? 'bg-error text-white' : item.tier === 'Medium' ? 'bg-warning text-white' : 'bg-tertiary text-white dark:text-[#061428]';
        let tierLabel = item.tier === 'High' ? 'อันตราย' : item.tier === 'Medium' ? 'ควรระวัง' : 'ปลอดภัย';
        
        const row = document.createElement('tr');
        row.className = 'cursor-pointer hover:bg-surface-container-highest/50 transition-colors';
        row.onclick = () => showHistoryDetail(index);
        
        row.innerHTML = `
            <td class="p-3 sm:p-5 text-[10px] sm:text-sm text-on-surface-variant truncate">${item.time}</td>
            <td class="p-3 sm:p-5 text-[10px] sm:text-sm text-primary font-mono truncate">${item.url}</td>
            <td class="p-3 sm:p-5 text-[10px] sm:text-sm font-semibold text-on-surface-variant">${item.primaryThreat || 'ไม่ระบุ'}</td>
            <td class="p-3 sm:p-5 text-right sm:text-left">
                <span class="text-[9px] sm:text-[11px] font-bold px-2 py-1 sm:px-3 sm:py-1.5 rounded-full ${badgeColor}">${tierLabel}</span>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function clearHistory() { 
    const modal = document.getElementById('confirmModal');
    modal.classList.remove('hidden'); 
    setTimeout(() => { 
        modal.classList.remove('opacity-0'); 
        document.getElementById('confirmModalContent').classList.remove('scale-95'); 
    }, 10); 
}

function closeConfirmModal() { 
    const modal = document.getElementById('confirmModal');
    modal.classList.add('opacity-0'); 
    document.getElementById('confirmModalContent').classList.add('scale-95'); 
    setTimeout(() => modal.classList.add('hidden'), 300); 
}

function executeClearHistory() { 
    localStorage.removeItem('scanHistory'); 
    loadHistoryTable(); 
    closeConfirmModal(); 
    showToast("ล้างประวัติเรียบร้อยแล้ว", "success"); 
}

function showHistoryDetail(index) {
    const history = JSON.parse(localStorage.getItem('scanHistory') || '[]');
    const item = history[index];
    if (!item) return;

    document.getElementById('detailModalUrl').textContent = item.url;
    document.getElementById('detailModalDomain').textContent = item.domain || "N/A";
    document.getElementById('detailModalTime').textContent = `สแกนเมื่อ: ${item.time}`;
    document.getElementById('detailModalMalicious').textContent = item.malicious || 0;

    const riskCard = document.getElementById('detailRiskCard');
    const riskIconContainer = document.getElementById('detailRiskIconContainer');
    const statusIcon = document.getElementById('detailStatusIcon');
    const riskStatus = document.getElementById('detailRiskStatus');
    const threatType = document.getElementById('detailThreatType');
    const bgIcon = document.getElementById('detailBgIcon');
    const mitigationSection = document.getElementById('detailMitigationSection');
    const mitigationIcon = document.getElementById('detailMitigationIcon');
    const mitigationTitle = document.getElementById('detailMitigationTitle');
    const mitigationContent = document.getElementById('detailMitigationContent');

    const pThreat = item.primaryThreat || 'ภัยคุกคาม';
    
    riskCard.className = "relative overflow-hidden rounded-[2rem] border p-6 mb-6 transition-all duration-300";
    riskIconContainer.className = "flex h-16 w-16 items-center justify-center rounded-full text-white shadow-lg shrink-0";

    if (item.tier === 'High') {
        riskCard.classList.add('bg-error/10', 'border-error/30', 'text-error');
        riskIconContainer.classList.add('bg-error');
        statusIcon.textContent = "gpp_bad"; bgIcon.textContent = "gpp_bad"; riskStatus.textContent = "อันตรายมาก"; threatType.textContent = `ตรวจพบ: ${pThreat}`;
        mitigationSection.className = "w-full rounded-2xl border border-error/20 bg-error/5 p-5 mb-8";
        mitigationIcon.className = "material-symbols-outlined text-error text-2xl shrink-0"; mitigationIcon.textContent = "report";
        mitigationTitle.className = "text-base font-bold text-error"; mitigationTitle.textContent = "ควรทำอย่างไร?";
        mitigationContent.className = "text-sm leading-relaxed text-error/80";
        mitigationContent.innerHTML = `<p><strong>หยุดการใช้งานทันที:</strong> เว็บไซต์นี้มีความเสี่ยงสูงที่จะขโมยข้อมูลหรือติดตั้งไวรัส</p><p class="mt-2"><strong>คำแนะนำ:</strong> ปิดหน้านี้และลบประวัติการเข้าชมล่าสุดของคุณทันที</p>`;
    } else if (item.tier === 'Medium') {
        riskCard.classList.add('bg-warning/10', 'border-warning/30', 'text-warning-dark');
        riskIconContainer.classList.add('bg-warning');
        statusIcon.textContent = "warning"; bgIcon.textContent = "warning"; riskStatus.textContent = "ควรระวัง"; threatType.textContent = `พบความผิดปกติ: ${pThreat}`;
        mitigationSection.className = "w-full rounded-2xl border border-warning/20 bg-warning/5 p-5 mb-8";
        mitigationIcon.className = "material-symbols-outlined text-warning text-2xl shrink-0"; mitigationIcon.textContent = "priority_high";
        mitigationTitle.className = "text-base font-bold text-warning-dark"; mitigationTitle.textContent = "ข้อควรระวัง";
        mitigationContent.className = "text-sm leading-relaxed text-warning-dark/80";
        mitigationContent.innerHTML = `<p><strong>ตรวจสอบที่มา:</strong> เว็บไซต์นี้มีประวัติที่น่าสงสัย หรืออาจเป็นเว็บไซต์ใหม่ที่ยังไม่มีการยืนยัน</p><p class="mt-2"><strong>คำแนะนำ:</strong> ห้ามกรอกรหัสผ่าน หรือข้อมูลบัตรเครดิตในหน้านี้เด็ดขาด</p>`;
    } else {
        riskCard.classList.add('bg-tertiary/10', 'border-tertiary/30', 'text-tertiary');
        riskIconContainer.classList.add('bg-tertiary');
        statusIcon.textContent = "verified_user"; bgIcon.textContent = "verified_user"; riskStatus.textContent = "ปลอดภัย"; threatType.textContent = "ไม่พบสิ่งผิดปกติจากการตรวจสอบ";
        mitigationSection.className = "w-full rounded-2xl border border-tertiary/20 bg-tertiary/5 p-5 mb-8";
        mitigationIcon.className = "material-symbols-outlined text-tertiary text-2xl shrink-0"; mitigationIcon.textContent = "check_circle";
        mitigationTitle.className = "text-base font-bold text-tertiary"; mitigationTitle.textContent = "สถานะปกติ";
        mitigationContent.className = "text-sm leading-relaxed text-tertiary/80";
        mitigationContent.innerHTML = `<p><strong>พร้อมใช้งาน:</strong> ไม่พบร่องรอยของภัยคุกคามในฐานข้อมูลปัจจุบัน</p><p class="mt-2"><strong>คำแนะนำ:</strong> คุณสามารถใช้งานเว็บไซต์นี้ได้ตามปกติ</p>`;
    }

    // 🟢 แก้ไขปุ่มดูรายงานให้กดแล้วส่งฟอร์ม (POST) ไปยัง /scan
    const reportBtn = document.getElementById('detailViewFullReport');
    if (reportBtn) {
        reportBtn.onclick = function(e) {
            e.preventDefault();
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = '/scan';
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = 'url';
            input.value = item.url;
            form.appendChild(input);
            document.body.appendChild(form);
            form.submit();
        };
    }

    const modal = document.getElementById('detailModal');
    modal.classList.remove('hidden'); 
    document.body.classList.add('modal-open');
    setTimeout(() => { 
        modal.classList.remove('opacity-0'); 
        document.getElementById('detailModalContent').classList.remove('scale-95'); 
    }, 10);
}

function closeDetailModal() {
    const modal = document.getElementById('detailModal');
    modal.classList.add('opacity-0'); 
    document.getElementById('detailModalContent').classList.add('scale-95'); 
    document.body.classList.remove('modal-open');
    setTimeout(() => modal.classList.add('hidden'), 300);
}