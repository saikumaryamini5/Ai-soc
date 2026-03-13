// Setup Chart.js Defaults
Chart.defaults.color = '#a0aec0';
Chart.defaults.font.family = "'Inter', sans-serif";

// Initialize Line Chart (Network Traffic, Threat Activity, Login Attempts)
const ctxLine = document.getElementById('lineChart').getContext('2d');

const gradientCyan = ctxLine.createLinearGradient(0, 0, 0, 400);
gradientCyan.addColorStop(0, 'rgba(0, 229, 255, 0.5)');
gradientCyan.addColorStop(1, 'rgba(0, 229, 255, 0)');

const gradientPink = ctxLine.createLinearGradient(0, 0, 0, 400);
gradientPink.addColorStop(0, 'rgba(255, 0, 200, 0.5)');
gradientPink.addColorStop(1, 'rgba(255, 0, 200, 0)');

const gradientGreen = ctxLine.createLinearGradient(0, 0, 0, 400);
gradientGreen.addColorStop(0, 'rgba(0, 255, 149, 0.5)');
gradientGreen.addColorStop(1, 'rgba(0, 255, 149, 0)');

const lineChart = new Chart(ctxLine, {
    type: 'line',
    data: {
        labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00', '24:00'],
        datasets: [
            {
                label: 'Network Traffic (GB/s)',
                data: [12, 19, 15, 25, 22, 30, 28],
                borderColor: '#00e5ff',
                backgroundColor: gradientCyan,
                borderWidth: 2,
                tension: 0.4,
                fill: true,
                pointBackgroundColor: '#0f001a',
                pointBorderColor: '#00e5ff',
                pointHoverBackgroundColor: '#00e5ff',
                pointHoverBorderColor: '#fff',
                pointRadius: 4,
                pointHoverRadius: 6
            },
            {
                label: 'Threat Activity',
                data: [5, 12, 8, 15, 10, 20, 15],
                borderColor: '#ff00c8',
                backgroundColor: gradientPink,
                borderWidth: 2,
                tension: 0.4,
                fill: true,
                pointBackgroundColor: '#0f001a',
                pointBorderColor: '#ff00c8',
                pointRadius: 4,
                pointHoverRadius: 6
            },
            {
                label: 'Login Attempts (k)',
                data: [30, 45, 60, 40, 50, 80, 55],
                borderColor: '#00ff95',
                backgroundColor: gradientGreen,
                borderWidth: 2,
                tension: 0.4,
                fill: true,
                pointBackgroundColor: '#0f001a',
                pointBorderColor: '#00ff95',
                pointRadius: 4,
                pointHoverRadius: 6
            }
        ]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'top',
                labels: {
                    usePointStyle: true,
                    boxWidth: 8,
                    padding: 20
                }
            },
            tooltip: {
                backgroundColor: 'rgba(30, 0, 51, 0.9)',
                titleColor: '#fff',
                bodyColor: '#a0aec0',
                borderColor: '#00e5ff',
                borderWidth: 1,
                padding: 10,
                displayColors: true,
                boxPadding: 4
            }
        },
        scales: {
            y: {
                grid: {
                    color: 'rgba(255, 255, 255, 0.05)',
                    drawBorder: false
                }
            },
            x: {
                grid: {
                    color: 'rgba(255, 255, 255, 0.05)',
                    drawBorder: false
                }
            }
        },
        interaction: {
            mode: 'index',
            intersect: false,
        },
        animation: {
            duration: 2000,
            easing: 'easeOutQuart'
        }
    }
});

// Heatmap Style Bar Chart (Threat Distribution)
const ctxBar = document.getElementById('barChart').getContext('2d');
const barChart = new Chart(ctxBar, {
    type: 'bar',
    data: {
        labels: ['DDoS', 'Phishing', 'Malware', 'SQLi', 'XSS', 'Brute Force'],
        datasets: [{
            label: 'Incident Count',
            data: [65, 45, 80, 30, 25, 50],
            backgroundColor: [
                'rgba(255, 0, 200, 0.8)',
                'rgba(0, 229, 255, 0.8)',
                'rgba(255, 0, 200, 0.8)',
                'rgba(0, 255, 149, 0.8)',
                'rgba(0, 229, 255, 0.8)',
                'rgba(0, 255, 149, 0.8)'
            ],
            borderColor: [
                '#ff00c8',
                '#00e5ff',
                '#ff00c8',
                '#00ff95',
                '#00e5ff',
                '#00ff95'
            ],
            borderWidth: 1,
            borderRadius: 6,
            hoverBackgroundColor: [
                'rgba(255, 0, 200, 1)',
                'rgba(0, 229, 255, 1)',
                'rgba(255, 0, 200, 1)',
                'rgba(0, 255, 149, 1)',
                'rgba(0, 229, 255, 1)',
                'rgba(0, 255, 149, 1)'
            ]
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                display: false
            },
            tooltip: {
                backgroundColor: 'rgba(30, 0, 51, 0.9)',
                titleColor: '#fff',
                bodyColor: '#a0aec0',
                borderColor: '#ff00c8',
                borderWidth: 1,
                padding: 10
            }
        },
        scales: {
            y: {
                grid: {
                    color: 'rgba(255, 255, 255, 0.05)',
                    drawBorder: false
                }
            },
            x: {
                grid: {
                    display: false
                }
            }
        },
        animation: {
            duration: 2000,
            easing: 'easeOutBounce'
        }
    }
});

// Animate Circular Progress on load
setTimeout(() => {
    document.getElementById('circle1').style.strokeDasharray = '75, 100';
    document.getElementById('circle2').style.strokeDasharray = '40, 100';
    document.getElementById('circle3').style.strokeDasharray = '15, 100';
}, 500);

// Live Log Updates Simulation
const activitiesLog = document.getElementById('activities-log');
const logs = [
    { type: 'critical', msg: 'Unauthorized access attempt detected from IP 192.168.1.50', time: 'Just now' },
    { type: 'warning', msg: 'Multiple failed logins for Admin account', time: '2 mins ago' },
    { type: 'info', msg: 'Firewall rules updated successfully', time: '5 mins ago' },
    { type: 'critical', msg: 'Malware signature matched in payload', time: '10 mins ago' },
    { type: 'warning', msg: 'High network traffic on port 443', time: '15 mins ago' },
    { type: 'info', msg: 'Daily backup completed successfully', time: '20 mins ago' },
    { type: 'warning', msg: 'Unusual spike in CPU usage on Server-02', time: '25 mins ago' }
];

let logIndex = 0;

// Initialize first 4 logs
for(let i=0; i<4; i++) {
    addLog(logs[i]);
    logIndex++;
}

function addLog(log) {
    const div = document.createElement('div');
    div.className = `log-item ${log.type} pl-6 pb-4 transform transition-all duration-500 opacity-0 translate-y-4`;
    div.innerHTML = `
        <div class="text-xs text-gray-400 mb-1 flex justify-between">
            <span>${log.time}</span>
            ${log.type === 'critical' ? '<span class="text-[10px] bg-pink-500 text-white px-1 rounded">CRITICAL</span>' : ''}
        </div>
        <div class="text-sm ${log.type === 'critical' ? 'text-pink-500 font-bold' : log.type === 'warning' ? 'text-yellow-400' : 'text-gray-300'}">${log.msg}</div>
    `;
    
    activitiesLog.prepend(div);
    
    // Trigger animation
    setTimeout(() => {
        div.classList.remove('opacity-0', 'translate-y-4');
    }, 50);

    if(activitiesLog.children.length > 6) {
        activitiesLog.removeChild(activitiesLog.lastChild);
    }
}

setInterval(() => {
    if(logIndex >= logs.length) logIndex = 0;
    const log = logs[logIndex];
    log.time = 'Just now'; // Update time for illusion of real-time
    logIndex++;
    addLog(log);
}, 6000);

// Calendar generation
const calendarDays = document.getElementById('calendar-days');
const date = new Date();
const currentMonth = date.getMonth();
const currentYear = date.getFullYear();
document.getElementById('calendar-month').innerText = date.toLocaleString('default', { month: 'long', year: 'numeric' });

const firstDayIndex = new Date(currentYear, currentMonth, 1).getDay();
const lastDay = new Date(currentYear, currentMonth + 1, 0).getDate();

// Empty slots before 1st day
for(let i = 1; i <= firstDayIndex; i++) {
    const div = document.createElement('div');
    calendarDays.appendChild(div);
}

// Days of month
for(let i = 1; i <= lastDay; i++) {
    const div = document.createElement('div');
    div.className = 'calendar-day text-sm text-gray-300 hover:scale-110';
    div.innerText = i;
    if(i === date.getDate()) {
        div.classList.add('active');
        // Add ping animation locally to current day
        div.innerHTML = `<span class="relative flex h-full w-full items-center justify-center">${i}
                            <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-pink-400 opacity-20"></span>
                         </span>`;
    }
    calendarDays.appendChild(div);
}

// Animate Progress Bars Bottom Right
setTimeout(() => {
    document.getElementById('fw-health').style.width = '92%';
    document.getElementById('sys-health').style.width = '78%';
    document.getElementById('srv-load').style.width = '64%';
    document.getElementById('threat-score').style.width = '35%';
    document.getElementById('net-usage').style.width = '88%';
}, 1000);

// Update Header Clock
setInterval(() => {
    const now = new Date();
    document.getElementById('current-time').innerText = 'UTC ' + now.toISOString().split('T')[1].split('.')[0];
}, 1000);
