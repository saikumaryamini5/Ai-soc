// 1. Sidebar Toggle Logic for Mobile
const sidebar = document.getElementById('sidebar');
const mobileOverlay = document.getElementById('mobile-overlay');
const openSidebarBtn = document.getElementById('open-sidebar');
const closeSidebarBtn = document.getElementById('close-sidebar');

function toggleSidebar(show) {
    if(show) {
        sidebar.classList.remove('-translate-x-full');
        mobileOverlay.classList.remove('hidden');
        // slight delay for fade in
        setTimeout(() => mobileOverlay.classList.remove('opacity-0'), 10);
    } else {
        sidebar.classList.add('-translate-x-full');
        mobileOverlay.classList.add('opacity-0');
        setTimeout(() => mobileOverlay.classList.add('hidden'), 300);
    }
}

if(openSidebarBtn) openSidebarBtn.addEventListener('click', () => toggleSidebar(true));
if(closeSidebarBtn) closeSidebarBtn.addEventListener('click', () => toggleSidebar(false));
if(mobileOverlay) mobileOverlay.addEventListener('click', () => toggleSidebar(false));


// 2. Live Header Clock
function updateClock() {
    const clockEl = document.getElementById('live-clock');
    if(!clockEl) return;
    const now = new Date();
    const timeStr = now.toISOString().split('T')[1].split('.')[0];
    clockEl.innerText = timeStr + ' UTC';
}
setInterval(updateClock, 1000);
updateClock();


// 3. Chart.js Global Setup
Chart.defaults.color = '#94a3b8';
Chart.defaults.font.family = "'Plus Jakarta Sans', sans-serif";
Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(15, 0, 26, 0.9)';
Chart.defaults.plugins.tooltip.titleColor = '#fff';
Chart.defaults.plugins.tooltip.padding = 12;
Chart.defaults.plugins.tooltip.cornerRadius = 8;
Chart.defaults.plugins.tooltip.borderColor = 'rgba(255, 255, 255, 0.1)';
Chart.defaults.plugins.tooltip.borderWidth = 1;


// 4. Main Line Chart (Network & Threats)
const ctxLine = document.getElementById('mainLineChart');
if(ctxLine) {
    const lineCtx = ctxLine.getContext('2d');
    
    // Gradients
    const gradCyan = lineCtx.createLinearGradient(0, 0, 0, 400);
    gradCyan.addColorStop(0, 'rgba(0, 229, 255, 0.4)');
    gradCyan.addColorStop(1, 'rgba(0, 229, 255, 0)');

    const gradPink = lineCtx.createLinearGradient(0, 0, 0, 400);
    gradPink.addColorStop(0, 'rgba(255, 0, 200, 0.4)');
    gradPink.addColorStop(1, 'rgba(255, 0, 200, 0)');

    const gradGreen = lineCtx.createLinearGradient(0, 0, 0, 400);
    gradGreen.addColorStop(0, 'rgba(0, 255, 149, 0.3)');
    gradGreen.addColorStop(1, 'rgba(0, 255, 149, 0)');

    new Chart(lineCtx, {
        type: 'line',
        data: {
            labels: ['00:00', '02:00', '04:00', '06:00', '08:00', '10:00', '12:00', '14:00', '16:00', '18:00', '20:00', '22:00', '24:00'],
            datasets: [
                {
                    label: 'Network Traffic (TB)',
                    data: [12, 14, 11, 8, 22, 35, 42, 38, 45, 50, 30, 20, 15],
                    borderColor: '#00e5ff',
                    backgroundColor: gradCyan,
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true,
                    pointBackgroundColor: '#0f001a',
                    pointBorderColor: '#00e5ff',
                    pointBorderWidth: 2,
                    pointRadius: 3,
                    pointHoverRadius: 6,
                    pointHoverBackgroundColor: '#00e5ff'
                },
                {
                    label: 'Threat Activity',
                    data: [2, 3, 1, 0, 5, 15, 12, 25, 18, 10, 8, 4, 3],
                    borderColor: '#ff00c8',
                    backgroundColor: gradPink,
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true,
                    pointBackgroundColor: '#0f001a',
                    pointBorderColor: '#ff00c8',
                    pointBorderWidth: 2,
                    pointRadius: 3,
                    pointHoverRadius: 6,
                    pointHoverBackgroundColor: '#ff00c8'
                },
                {
                    label: 'Login Attempts (K)',
                    data: [20, 18, 15, 10, 40, 80, 95, 85, 90, 70, 45, 30, 22],
                    borderColor: '#00ff95',
                    backgroundColor: gradGreen,
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true,
                    pointBackgroundColor: '#0f001a',
                    pointBorderColor: '#00ff95',
                    pointBorderWidth: 2,
                    pointRadius: 3,
                    pointHoverRadius: 6,
                    pointHoverBackgroundColor: '#00ff95'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: {
                    position: 'top',
                    align: 'end',
                    labels: {
                        usePointStyle: true,
                        boxWidth: 8,
                        padding: 20,
                        color: '#cbd5e1',
                        font: { size: 12, weight: '500' }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255, 255, 255, 0.03)', drawBorder: false },
                    ticks: { maxTicksLimit: 6, padding: 10 }
                },
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.03)', drawBorder: false },
                    ticks: { maxTicksLimit: 8, padding: 10 }
                }
            },
            animation: {
                duration: 2000,
                easing: 'easeOutQuart'
            }
        }
    });
}


// 5. Threat Distribution Bar Chart
const ctxBar = document.getElementById('barChart');
if(ctxBar) {
    const barCtx = ctxBar.getContext('2d');
    new Chart(barCtx, {
        type: 'bar',
        data: {
            labels: ['Malware', 'Phishing', 'DDoS', 'SQLi', 'Brute Force', 'XSS', 'Insider'],
            datasets: [{
                label: 'Incidents Blocked',
                data: [145, 89, 210, 45, 120, 34, 12],
                backgroundColor: [
                    'rgba(0, 229, 255, 0.8)',
                    'rgba(255, 0, 200, 0.8)',
                    'rgba(0, 255, 149, 0.8)',
                    'rgba(168, 85, 247, 0.8)',
                    'rgba(234, 179, 8, 0.8)',
                    'rgba(244, 63, 94, 0.8)',
                    'rgba(148, 163, 184, 0.8)'
                ],
                borderRadius: 4,
                borderSkipped: false,
                barThickness: 16
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    grid: { color: 'rgba(255, 255, 255, 0.03)', drawBorder: false },
                    ticks: { padding: 10 }
                },
                x: {
                    grid: { display: false, drawBorder: false },
                    ticks: { color: '#94a3b8', font: { size: 11 } }
                }
            },
            animation: {
                duration: 1500,
                easing: 'easeOutBounce'
            }
        }
    });
}


// 6. Live Alerts Feed Population
const alertContainer = document.getElementById('alert-feed-container');

const sampleAlerts = [
    { type: 'critical', title: 'Unauthorized Execution', time: 'Just now', msg: 'Powershell invoked with obfuscated payload on Desktop-A49', color: 'pink-500', icon: 'fa-triangle-exclamation' },
    { type: 'warning', title: 'Brute Force Attempt', time: '1m ago', msg: '45 failed login attempts to SSH gateway from 192.168.x.x', color: 'yellow-400', icon: 'fa-shield-halved' },
    { type: 'info', title: 'IP Blacklisted', time: '3m ago', msg: 'Successfully appended malicious IP to firewall deny-list.', color: 'cyan-400', icon: 'fa-ban' },
    { type: 'critical', title: 'Data Exfiltration', time: '8m ago', msg: 'Abnormal outbound traffic spike on port 443 detected toward known bad ASN.', color: 'pink-500', icon: 'fa-network-wired' }
];

function createAlertHTML(alert) {
    const isCritical = alert.type === 'critical';
    const bgOpacity = isCritical ? 'bg-pink-900/20' : 'bg-white/5';
    const borderCls = isCritical ? 'border-pink-500/30' : 'border-white/5';
    const glowClass = isCritical ? 'shadow-[0_0_15px_rgba(255,0,200,0.15)]' : '';

    return `
        <div class="p-3 rounded-lg border ${borderCls} ${bgOpacity} ${glowClass} animate-slide-down cursor-pointer hover:bg-white/10 transition-colors group">
            <div class="flex justify-between items-start mb-1.5">
                <div class="flex items-center gap-2">
                    <i class="fa-solid ${alert.icon} text-${alert.color} ${isCritical ? 'animate-pulse' : ''}"></i>
                    <span class="text-${alert.color} font-bold text-xs uppercase tracking-wider">${alert.title}</span>
                </div>
                <span class="text-[10px] text-gray-500 font-mono">${alert.time}</span>
            </div>
            <p class="text-xs text-gray-300 leading-relaxed font-sans">${alert.msg}</p>
        </div>
    `;
}

if(alertContainer) {
    // Initial load
    sampleAlerts.forEach(alert => {
        alertContainer.insertAdjacentHTML('beforeend', createAlertHTML(alert));
    });

    // Simulate incoming
    setInterval(() => {
        const randAlert = sampleAlerts[Math.floor(Math.random() * sampleAlerts.length)];
        const newAlert = { ...randAlert, time: 'Just now' };
        alertContainer.insertAdjacentHTML('afterbegin', createAlertHTML(newAlert));
        
        if(alertContainer.children.length > 5) {
            alertContainer.removeChild(alertContainer.lastElementChild);
        }
    }, 8000);
}


// 7. Calendar Grid Builder
const calGrid = document.getElementById('calendar-grid');
const monthDisp = document.getElementById('month-display');

if(calGrid && monthDisp) {
    const today = new Date();
    const curMonth = today.getMonth();
    const curYear = today.getFullYear();
    const curDate = today.getDate();

    const shortMonths = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
    monthDisp.innerText = `${shortMonths[curMonth]} ${curYear}`;

    const firstDay = new Date(curYear, curMonth, 1).getDay();
    const totalDays = new Date(curYear, curMonth + 1, 0).getDate();

    // Empties
    for(let i=0; i<firstDay; i++) {
        calGrid.innerHTML += `<div></div>`;
    }

    // Days
    for(let i=1; i<=totalDays; i++) {
        const isToday = i === curDate;
        if(isToday) {
            calGrid.innerHTML += `
                <div class="aspect-square flex justify-center items-center text-xs font-semibold rounded-md bg-pink-500 text-white shadow-[0_0_10px_rgba(255,0,200,0.6)] relative z-10 cursor-pointer">
                    ${i}
                    <div class="absolute inset-0 rounded-md bg-pink-500 animate-ping opacity-30 -z-10"></div>
                </div>
            `;
        } else {
            calGrid.innerHTML += `<div class="aspect-square flex justify-center items-center text-xs font-medium text-gray-400 hover:text-cyan-400 hover:bg-cyan-500/10 cursor-pointer rounded-md transition-colors">${i}</div>`;
        }
    }
}
