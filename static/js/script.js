const API_BASE = '/api';
const REFRESH_INTERVAL = 5000;

let trafficChartInstance = null;
let threatPieChartInstance = null;

const formatTimestamp = (isoStr) => new Date(isoStr).toLocaleString();

const getSeverityBadge = (severity) => {
    const s = severity.toLowerCase();
    if (s === 'critical') return `<span class="badge badge-critical">CRITICAL</span>`;
    if (s === 'high') return `<span class="badge badge-high">HIGH</span>`;
    if (s === 'medium') return `<span class="badge badge-medium">MOD</span>`;
    return `<span class="badge badge-low">LOW</span>`;
};

const getStatusColor = (status) => {
    const s = status.toLowerCase();
    if (s === 'blocked') return '<span class="text-red-400"><i class="fa-solid fa-ban text-xs mr-1"></i> Blocked</span>';
    if (s === 'allowed') return '<span class="text-green-400"><i class="fa-solid fa-check text-xs mr-1"></i> Allowed</span>';
    return '<span class="text-yellow-400"><i class="fa-solid fa-flag text-xs mr-1"></i> Flagged</span>';
};

const initCharts = () => {
    const trafficCanvas = document.getElementById('trafficChart');
    if (trafficCanvas) {
        const trafficCtx = trafficCanvas.getContext('2d');
        const gradientFill = trafficCtx.createLinearGradient(0, 0, 0, 400);
        gradientFill.addColorStop(0, 'rgba(14, 165, 233, 0.4)');
        gradientFill.addColorStop(1, 'rgba(14, 165, 233, 0.0)');

        trafficChartInstance = new Chart(trafficCtx, {
            type: 'line',
            data: {
                labels: ['10:00', '10:05', '10:10', '10:15', '10:20', '10:25'],
                datasets: [{
                    label: 'Traffic Flow',
                    data: [120, 190, 85, 205, 140, 220],
                    borderColor: '#0ea5e9',
                    backgroundColor: gradientFill,
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true,
                    pointBackgroundColor: '#0f172a',
                    pointBorderColor: '#0ea5e9',
                    pointRadius: 4,
                    pointHoverRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        border: { dash: [5, 5] },
                        ticks: { color: '#94a3b8' }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { color: '#94a3b8' }
                    }
                },
                animation: { duration: 0 }
            }
        });
    }

    const pieCanvas = document.getElementById('threatPieChart');
    if (pieCanvas) {
        const pieCtx = pieCanvas.getContext('2d');
        threatPieChartInstance = new Chart(pieCtx, {
            type: 'doughnut',
            data: {
                labels: ['Malware', 'Phishing', 'DDoS', 'Intrusion'],
                datasets: [{
                    data: [35, 25, 20, 20],
                    backgroundColor: ['#ef4444', '#f59e0b', '#8b5cf6', '#0ea5e9'],
                    borderWidth: 0,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '75%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#e2e8f0', padding: 20, boxWidth: 12, usePointStyle: true }
                    }
                },
                animation: { duration: 0 }
            }
        });
    }
};

const updateStatsUI = (stats) => {
    if (!stats) return;
    document.getElementById('statTotalEvents').textContent = stats.total_events.toLocaleString();
    document.getElementById('statCriticalAlerts').textContent = stats.critical_alerts.toLocaleString();
    document.getElementById('statActiveThreats').textContent = stats.active_threats.toLocaleString();
    document.getElementById('statResolvedThreats').textContent = stats.resolved_threats.toLocaleString();
};

const updateLogsTableUI = (logs) => {
    const tbody = document.getElementById('logsTableBody');
    if (!logs || !logs.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="p-4 text-center text-gray-500">No events found.</td></tr>';
        return;
    }

    const fragment = document.createDocumentFragment();
    logs.slice(0, 15).forEach(log => {
        const tr = document.createElement('tr');
        if (log.severity.toLowerCase() === 'critical') {
            tr.className = 'bg-red-900/10 border-l-[3px] border-l-red-500';
        }
        tr.innerHTML = `
            <td class="p-3 font-mono text-xs text-gray-400 whitespace-nowrap">${formatTimestamp(log.timestamp)}</td>
            <td class="p-3 font-mono text-sm">${log.source_ip || 'N/A'}</td>
            <td class="p-3 font-mono text-sm text-gray-400">${log.destination_ip || 'N/A'}</td>
            <td class="p-3 font-medium">${log.event_type || 'Unknown'}</td>
            <td class="p-3">${getSeverityBadge(log.severity)}</td>
            <td class="p-3">${getStatusColor(log.status)}</td>
        `;
        fragment.appendChild(tr);
    });

    tbody.innerHTML = '';
    tbody.appendChild(fragment);
};

const fetchDashboardData = async () => {
    try {
        const [statsRes, logsRes] = await Promise.all([
            fetch(`${API_BASE}/stats`),
            fetch(`${API_BASE}/logs`)
        ]);

        if (statsRes.ok) updateStatsUI(await statsRes.json());
        if (logsRes.ok) updateLogsTableUI(await logsRes.json());

        if (trafficChartInstance) {
            const data = trafficChartInstance.data.datasets[0].data;
            data.shift();
            data.push(Math.floor(Math.random() * 150) + 50);
            trafficChartInstance.update();
        }
    } catch (error) {
        console.error('Data Fetch Error:', error);
    }
};

const startClock = () => {
    const clockDisplay = document.getElementById('clockDisplay');
    setInterval(() => {
        clockDisplay.textContent = new Date().toLocaleTimeString('en-US', { hour12: false });
    }, 1000);
};

document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    startClock();
    fetchDashboardData();
    setInterval(fetchDashboardData, REFRESH_INTERVAL);

    const toggleSidebarBtn = document.getElementById('toggleSidebarBtn');
    const closeSidebarBtn = document.getElementById('closeSidebarBtn');
    const sidebar = document.querySelector('.sidebar');
    
    if (toggleSidebarBtn && sidebar) {
        toggleSidebarBtn.addEventListener('click', () => {
            sidebar.classList.remove('hidden');
            sidebar.classList.add('flex');
            sidebar.style.zIndex = '50';
        });
    }

    if (closeSidebarBtn && sidebar) {
        closeSidebarBtn.addEventListener('click', () => {
            sidebar.classList.add('hidden');
            sidebar.classList.remove('flex');
        });
    }
});
