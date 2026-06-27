const threatColorMap = {
    'malicious':  { bg: 'bg-pink-100',   text: 'text-pink-600',   hex: '#ec4899', keywords: ['malicious', 'threat', 'danger'] },
    'phishing':   { bg: 'bg-orange-100', text: 'text-orange-600', hex: '#f97316', keywords: ['phish', 'scam', 'fraud', 'fake', 'credential'] },
    'malware':    { bg: 'bg-red-100',    text: 'text-red-600',    hex: '#ef4444', keywords: ['malware', 'trojan', 'ransom', 'virus', 'worm', 'backdoor', 'spyware', 'bot', 'adware', 'exploit', 'downloader'] },
    'suspicious': { bg: 'bg-yellow-100', text: 'text-yellow-600', hex: '#eab308', keywords: ['suspicious', 'pup', 'spam', 'risk'] },
    'harmless':   { bg: 'bg-green-100',  text: 'text-green-600',  hex: '#10b881', keywords: ['harmless', 'clean', 'safe', 'trusted'] },
    'default':    { bg: 'bg-slate-100',  text: 'text-slate-600',  hex: '#64748b', keywords: [] }
};

function getThreatStyle(name, category = '') {
    const rawType = String(name || '').toLowerCase();
    const cat = String(category || '').toLowerCase();
    if (threatColorMap.phishing.keywords.some(kw => rawType.includes(kw))) return threatColorMap.phishing;
    if (threatColorMap.malware.keywords.some(kw => rawType.includes(kw))) return threatColorMap.malware;
    if (threatColorMap.malicious.keywords.some(kw => rawType.includes(kw)) || cat === 'malicious') return threatColorMap.malicious;
    if (threatColorMap.suspicious.keywords.some(kw => rawType.includes(kw)) || cat === 'suspicious') return threatColorMap.suspicious;
    if (threatColorMap.harmless.keywords.some(kw => rawType.includes(kw)) || cat === 'harmless') return threatColorMap.harmless;
    return threatColorMap.default;
}

function toggleTheme() {
    const html = document.documentElement;
    if (html.classList.contains('dark')) { html.classList.remove('dark'); localStorage.setItem('theme', 'light'); updateThemeIcons('dark_mode'); } 
    else { html.classList.add('dark'); localStorage.setItem('theme', 'dark'); updateThemeIcons('light_mode'); }
    window.dispatchEvent(new Event('themeChanged'));
}

function updateThemeIcons(iconName) {
    if(document.getElementById('themeIconDesktop')) document.getElementById('themeIconDesktop').innerText = iconName;
    if(document.getElementById('themeIconMobile')) document.getElementById('themeIconMobile').innerText = iconName;
}

function showToast(message, type = 'error') {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = 'pointer-events-auto flex items-center gap-3 px-4 sm:px-5 py-3 sm:py-4 rounded-xl border shadow-2xl backdrop-blur-xl transform transition-all duration-300 translate-x-[120%] opacity-0';
    let colors = type === 'error' ? 'bg-error/10 border-error/30 text-error' : type === 'success' ? 'bg-tertiary-container border-tertiary/30 text-tertiary' : 'bg-surface-container-highest border-outline/30 text-on-surface';
    let iconName = type === 'error' ? 'error' : type === 'success' ? 'check_circle' : 'info';
    toast.classList.add(...colors.split(' '));
    toast.innerHTML = `<span class="material-symbols-outlined filled shrink-0">${iconName}</span><span class="text-xs sm:text-sm font-medium mr-2 sm:mr-4 break-words"></span><button class="ml-auto opacity-70 hover:opacity-100 transition-opacity shrink-0" onclick="this.parentElement.remove()"><span class="material-symbols-outlined text-[18px]">close</span></button>`;
    toast.querySelector('span:nth-child(2)').textContent = message;
    container.appendChild(toast);
    requestAnimationFrame(() => toast.classList.remove('translate-x-[120%]', 'opacity-0'));
    setTimeout(() => { toast.classList.add('translate-x-[120%]', 'opacity-0'); setTimeout(() => toast.remove(), 300); }, 4000);
}

function toggleMobileNav() { document.getElementById('mobileNav')?.classList.toggle('hidden'); }
function closeMobileNav() { document.getElementById('mobileNav')?.classList.add('hidden'); }

document.addEventListener('DOMContentLoaded', () => { 
    if (localStorage.getItem('theme') === 'dark') updateThemeIcons('light_mode'); else updateThemeIcons('dark_mode');
});