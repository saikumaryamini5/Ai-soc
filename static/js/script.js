// Constants
const API_BASE_URL = 'http://127.0.0.1:5000/api';

// Initialize Charts
let mainThreatChart = null;
let trafficChart = null;
let threatActivityChart = null;
let loginAttemptsChart = null;

// Track if secondary charts are initialized
let secondaryChartsInit = false;

document.addEventListener('DOMContentLoaded', () => {
    initDashboard();
    setupEventListeners();
});

function setupEventListeners() {
    // Refresh button
    const refreshBtn = document.getElementById('refresh-btn');
    if(refreshBtn) refreshBtn.addEventListener('click', refreshData);
    
    // Search functionality
    const searchBtn = document.getElementById('search-btn');
    const searchInput = document.getElementById('search-input');
    
    if(searchBtn && searchInput) {
        searchBtn.addEventListener('click', () => { performSearch(searchInput.value); });
        searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') performSearch(searchInput.value);
        });
    }

    // Export PDF functionality
    const exportBtn = document.getElementById('export-btn');
    if(exportBtn) {
        exportBtn.addEventListener('click', () => {
            window.location.href = '/export/pdf';
        });
    }

    // Tab Switching functionality
    const navItems = document.querySelectorAll('.nav-item');
    const tabContents = document.querySelectorAll('.tab-content');

    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            
            // Remove active classes
            navItems.forEach(nav => nav.classList.remove('active'));
            tabContents.forEach(content => {
                content.classList.remove('block');
                content.classList.add('hidden');
            });
            
            // Add active class to clicked
            item.classList.add('active');
            const targetId = item.getAttribute('data-tab');
            const targetTab = document.getElementById(targetId);
            
            if (targetTab) {
                targetTab.classList.remove('hidden');
                targetTab.classList.add('block');
            }
            
            // If charts tab, initialize them once visible
            if (targetId === 'tab-charts' && !secondaryChartsInit) {
                initSecondaryCharts();
            }
        });
    });

    // Auto-refresh stats and alerts every 30 seconds
    setInterval(() => {
        fetchStats(true);
        fetchAlerts();
    }, 30000);
}

async function initDashboard() {
    await fetchStats(true); // true to initialize the chart
    await fetchLogs();
    await fetchAlerts();
}

async function refreshData() {
    const refreshBtn = document.getElementById('refresh-btn');
    if(!refreshBtn) return;
    
    const originalContent = refreshBtn.innerHTML;
    refreshBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Refreshing...';
    refreshBtn.disabled = true;
    
    try {
        await Promise.all([
            fetchStats(true),
            fetchLogs(),
            fetchAlerts()
        ]);
        const searchInput = document.getElementById('search-input');
        if(searchInput) searchInput.value = '';
    } catch (error) {
        console.error('Error refreshing data:', error);
    } finally {
        refreshBtn.innerHTML = originalContent;
        refreshBtn.disabled = false;
    }
}

async function fetchStats(updateChart = false) {
    try {
        const response = await fetch(`${API_BASE_URL}/stats`);
        const data = await response.json();
        
        const iElem = document.getElementById('stats-incidents');
        const aElem = document.getElementById('stats-alerts');
        const bElem = document.getElementById('stats-blocked-ips');
        
        if (iElem) iElem.textContent = data.incidents.toLocaleString();
        if (aElem) aElem.textContent = data.alerts.toLocaleString();
        if (bElem) bElem.textContent = data.blocked_ips.toLocaleString();
        
        if (updateChart && data.chart_data) {
            renderMainThreatChart(data.chart_data);
            if (secondaryChartsInit) {
                updateSecondaryCharts(data.chart_data);
            }
        }
    } catch (error) {
        console.error('Failed to fetch stats:', error);
    }
}

async function fetchLogs() {
    try {
        const response = await fetch(`${API_BASE_URL}/logs`);
        const data = await response.json();
        
        renderLogsTable(data);
    } catch (error) {
        console.error('Failed to fetch logs:', error);
    }
}

async function performSearch(query) {
    if (!query.trim()) {
        fetchLogs();
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/search?ip=${encodeURIComponent(query)}`);
        const data = await response.json();
        
        renderLogsTable(data);
    } catch (error) {
        console.error('Failed to search logs:', error);
    }
}


async function fetchAlerts() {
    try {
        const response = await fetch(`${API_BASE_URL}/alerts`);
        const data = await response.json();
        
        renderAlertsList(data);
    } catch (error) {
        console.error('Failed to fetch alerts:', error);
    }
}

function renderLogsTable(logs) {
    const tableBody = document.getElementById('logs-table-body');
    if(!tableBody) return;
    
    tableBody.innerHTML = '';
    
    if (logs.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 20px;">No logs match criteria</td></tr>';
        return;
    }
    
    const fragment = document.createDocumentFragment();

    logs.forEach(log => {
        const tr = document.createElement('tr');
        const dtStr = log.timestamp;
        let timeLabel = dtStr;
        try {
            // "2026-03-13T10:15:00Z" -> "2026-03-13 10:15"
            timeLabel = dtStr.replace('T', ' ').substring(0, 16)
        } catch(e) {}
        
        const severityClass = `severity-${log.severity.toLowerCase()}`;
        const statusClass = `status-${log.status.toLowerCase()}`;
        
        tr.innerHTML = `
            <td>${timeLabel}</td>
            <td class="monospaced">${log.source_ip}</td>
            <td class="monospaced">${log.destination_ip}</td>
            <td>${log.event_type}</td>
            <td><span class="severity-badge ${severityClass}">${log.severity}</span></td>
            <td class="${statusClass}" style="text-transform: capitalize; font-weight: 600;">${log.status}</td>
        `;
        fragment.appendChild(tr);
    });
    
    tableBody.appendChild(fragment);
}

function renderAlertsList(alerts) {
    const alertsContainer = document.getElementById('alerts-container');
    if(!alertsContainer) return;
    
    alertsContainer.innerHTML = '';
    
    if (alerts.length === 0) {
        alertsContainer.innerHTML = '<div style="text-align: center; color: var(--text-muted); padding: 20px;">No high or critical alerts</div>';
        return;
    }
    
    // Sort by timestamp descending
    alerts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    const fragment = document.createDocumentFragment();

    alerts.slice(0, 10).forEach(alert => {
        const item = document.createElement('div');
        item.className = `alert-item ${alert.severity}`;
        
        let timeLabel = alert.timestamp;
        try { timeLabel = timeLabel.split('T')[1].substring(0,5); } catch(e){}
        
        item.innerHTML = `
            <div class="alert-header">
                <div class="alert-title">
                    <i class="fas fa-exclamation-triangle"></i>
                    ${alert.event_type}
                </div>
                <div class="alert-time">${timeLabel}</div>
            </div>
            <div class="alert-details">
                <strong>Src:</strong> <span class="monospaced">${alert.source_ip}</span><br>
                <strong>Dst:</strong> <span class="monospaced">${alert.destination_ip}</span>
            </div>
            <div class="alert-actions">
                <button class="btn-small danger block-ip-btn" data-ip="${alert.source_ip}">
                    <i class="fas fa-ban"></i> Block IP
                </button>
            </div>
        `;
        fragment.appendChild(item);
    });
    
    alertsContainer.appendChild(fragment);
    
    document.querySelectorAll('.block-ip-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            blockIP(this.getAttribute('data-ip'));
        });
    });
}

async function blockIP(ip) {
    if (!confirm(`Are you sure you want to block IP address ${ip}?`)) {
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/block-ip`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip })
        });
        
        const result = await response.json();
        
        if (result.success) {
            alert(`Successfully blocked IP: ${ip}`);
            refreshData();
        } else {
            alert(`Failed to block IP: ${result.message}`);
        }
    } catch (error) {
        console.error('Error blocking IP:', error);
    }
}

// ---------------------------
// Chart Rendering Logic
// ---------------------------

const commonChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 0 }, // Disable animations for speed
    plugins: {
        legend: { position: 'top', labels: { color: '#e0e0e0', font: { family: 'Rajdhani', size: 12 } } },
        tooltip: {
            backgroundColor: 'rgba(15, 0, 26, 0.9)', titleColor: '#00e5ff', bodyColor: '#fff',
            borderColor: '#bd00ff', borderWidth: 1, padding: 8
        }
    },
    scales: {
        y: { grid: { color: 'rgba(189, 0, 255, 0.1)' }, ticks: { color: '#9b72cf' } },
        x: { grid: { color: 'rgba(189, 0, 255, 0.1)' }, ticks: { color: '#9b72cf' } }
    },
    interaction: { intersect: false, mode: 'index' }
};

function renderMainThreatChart(chartData) {
    const canvas = document.getElementById('mainThreatChart');
    if(!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    if (mainThreatChart) {
        mainThreatChart.data.labels = chartData.labels;
        mainThreatChart.data.datasets[0].data = chartData.traffic;
        mainThreatChart.data.datasets[1].data = chartData.alerts_trend;
        mainThreatChart.update();
        return;
    }
    
    const grad1 = ctx.createLinearGradient(0, 0, 0, 400);
    grad1.addColorStop(0, 'rgba(0, 229, 255, 0.4)'); grad1.addColorStop(1, 'rgba(0, 229, 255, 0)');
    
    const grad2 = ctx.createLinearGradient(0, 0, 0, 400);
    grad2.addColorStop(0, 'rgba(255, 0, 200, 0.4)'); grad2.addColorStop(1, 'rgba(255, 0, 200, 0)');

    mainThreatChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: chartData.labels,
            datasets: [
                {
                    label: 'Network Traffic (Mbs)',
                    data: chartData.traffic,
                    borderColor: '#00e5ff', backgroundColor: grad1, borderWidth: 2, fill: true, tension: 0.3, pointRadius: 0
                },
                {
                    label: 'Threat Alerts',
                    data: chartData.alerts_trend,
                    borderColor: '#ff00c8', backgroundColor: grad2, borderWidth: 2, fill: true, tension: 0.3, pointRadius: 0
                }
            ]
        },
        options: commonChartOptions
    });
}

function initSecondaryCharts() {
    secondaryChartsInit = true;
    
    // We fetch the stats once to seed the secondary charts
    fetch(`${API_BASE_URL}/stats`)
        .then(res => res.json())
        .then(data => {
            if(data.chart_data){
                updateSecondaryCharts(data.chart_data);
            }
        });
}

function updateSecondaryCharts(chartData) {
    // 1. Network Traffic Chart
    const ctxTraffic = document.getElementById('trafficChart')?.getContext('2d');
    if(ctxTraffic) {
        if(!trafficChart) {
            trafficChart = new Chart(ctxTraffic, {
                type: 'bar',
                data: {
                    labels: chartData.labels,
                    datasets: [{
                        label: 'Inbound Traffic',
                        data: chartData.traffic,
                        backgroundColor: '#00e5ff',
                        borderRadius: 4
                    }]
                },
                options: commonChartOptions
            });
        } else {
            trafficChart.data.labels = chartData.labels;
            trafficChart.data.datasets[0].data = chartData.traffic;
            trafficChart.update();
        }
    }

    // 2. Threat Activity Chart
    const ctxThreat = document.getElementById('threatActivityChart')?.getContext('2d');
    if(ctxThreat) {
        if(!threatActivityChart) {
            threatActivityChart = new Chart(ctxThreat, {
                type: 'line',
                data: {
                    labels: chartData.labels,
                    datasets: [{
                        label: 'Active Threats Detected',
                        data: chartData.alerts_trend,
                        borderColor: '#ff00c8',
                        backgroundColor: 'rgba(255,0,200,0.1)',
                        fill: true,
                        tension: 0.1
                    }]
                },
                options: commonChartOptions
            });
        } else {
            threatActivityChart.data.labels = chartData.labels;
            threatActivityChart.data.datasets[0].data = chartData.alerts_trend;
            threatActivityChart.update();
        }
    }

    // 3. Login Attempts Chart
    const ctxLogin = document.getElementById('loginAttemptsChart')?.getContext('2d');
    if(ctxLogin) {
        // Generate some fake login data based off existing points for realism
        const loginData = chartData.traffic.map(v => Math.floor(v / 4));
        const failData = chartData.alerts_trend.map(v => Math.floor(v / 2));
        
        if(!loginAttemptsChart) {
            loginAttemptsChart = new Chart(ctxLogin, {
                type: 'line',
                data: {
                    labels: chartData.labels,
                    datasets: [
                        { label: 'Successful Logins', data: loginData, borderColor: '#00ff95', tension: 0.2 },
                        { label: 'Failed Logins', data: failData, borderColor: '#ff3333', tension: 0.2 }
                    ]
                },
                options: commonChartOptions
            });
        } else {
            loginAttemptsChart.data.labels = chartData.labels;
            loginAttemptsChart.data.datasets[0].data = loginData;
            loginAttemptsChart.data.datasets[1].data = failData;
            loginAttemptsChart.update();
        }
    }
}

// ---------------------------
// Manual Log Analysis (from prior version)
// ---------------------------
async function analyzeLog() {
    const logInput = document.getElementById('raw-log-input');
    const resultDiv = document.getElementById('analysis-result');
    
    if(!logInput || !resultDiv) return;
    
    const val = logInput.value;
    if (!val.trim()) { alert("Please enter some log data to analyze."); return; }
    
    resultDiv.innerHTML = '<div class="text-center text-[var(--highlight-cyan)] mt-8"><i class="fas fa-spinner fa-spin text-2xl"></i><p class="mt-2">Analyzing...</p></div>';
    
    try {
        const response = await fetch(`${API_BASE_URL}/analyze-log`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ log: val })
        });
        
        const data = await response.json();
        if (data.success) {
            let bClass = 'severity-low';
            if (data.risk_factor === 'Medium') bClass = 'severity-medium';
            if (data.risk_factor === 'High') bClass = 'severity-high';
            if (data.risk_factor === 'Critical') bClass = 'severity-critical';
            
            let htmlList = data.findings.length ? `<ul class="list-disc pl-5 mt-2 text-sm text-[var(--highlight-cyan)]">${data.findings.map(f=>`<li>${f}</li>`).join('')}</ul>` : '<p class="text-sm mt-2 text-[var(--highlight-green)]">No threats found.</p>';
            
            resultDiv.innerHTML = `
                <h3 class="font-bold text-white border-b border-[rgba(189,0,255,0.2)] pb-2 mb-3">Analysis Results</h3>
                <div class="mb-2"><span class="text-sm text-[#9b72cf] uppercase">Risk Factor:</span> <span class="severity-badge ${bClass} ml-2">${data.risk_factor}</span></div>
                <div class="mb-2"><span class="text-sm text-[#9b72cf] uppercase">Risk Score:</span> <span class="font-bold text-lg ml-2 text-white">${data.risk_score}/100</span></div>
                <div><span class="text-sm text-[#9b72cf] uppercase">Findings:</span>${htmlList}</div>
            `;
        } else {
            resultDiv.innerHTML = `<div class="text-[var(--alert-red)] p-4">${data.error}</div>`;
        }
    } catch(e) {
        resultDiv.innerHTML = `<div class="text-[var(--alert-red)] p-4">Error connecting to engine.</div>`;
    }
}
