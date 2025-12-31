/**
 * LOTL Detector Dashboard - Main Application
 */

// Configuration
const API_BASE_URL = 'http://localhost:5000/api';
const REFRESH_INTERVAL = 30000; // 30 seconds
const ALERTS_PER_PAGE = 10;

// State
let currentAlerts = [];
let filteredAlerts = [];
let currentPage = 1;
let sortColumn = 'timestamp';
let sortDirection = 'desc';
let autoRefreshTimer = null;

// DOM Elements
const statusDot = document.getElementById('statusDot');
const statusText = document.getElementById('statusText');
const lastUpdated = document.getElementById('lastUpdated');
const totalAlertsBadge = document.querySelector('.badge-number');
const refreshBtn = document.getElementById('refreshBtn');

// Stats elements
const statTotal = document.getElementById('statTotal');
const statCritical = document.getElementById('statCritical');
const statHigh = document.getElementById('statHigh');
const statMedium = document.getElementById('statMedium');
const statLow = document.getElementById('statLow');

// Filter elements
const severityFilter = document.getElementById('severityFilter');
const platformFilter = document.getElementById('platformFilter');
const scoreFilter = document.getElementById('scoreFilter');
const scoreValue = document.getElementById('scoreValue');
const timeFilter = document.getElementById('timeFilter');
const applyFiltersBtn = document.getElementById('applyFiltersBtn');
const clearFiltersBtn = document.getElementById('clearFiltersBtn');

// Table elements
const alertsTableBody = document.getElementById('alertsTableBody');
const alertsCount = document.getElementById('alertsCount');
const prevPage = document.getElementById('prevPage');
const nextPage = document.getElementById('nextPage');
const pageInfo = document.getElementById('pageInfo');

// Export elements
const exportJsonBtn = document.getElementById('exportJsonBtn');
const exportCsvBtn = document.getElementById('exportCsvBtn');

// Modal elements
const alertModal = document.getElementById('alertModal');
const modalClose = document.getElementById('modalClose');
const modalTitle = document.getElementById('modalTitle');
const modalBody = document.getElementById('modalBody');

// Toast element
const errorToast = document.getElementById('errorToast');
const toastMessage = document.getElementById('toastMessage');

/**
 * Initialize the dashboard
 */
async function init() {
    console.log('Initializing LOTL Detector Dashboard...');

    // Set up event listeners
    setupEventListeners();

    // Load initial data
    await loadDashboard();

    // Start auto-refresh
    startAutoRefresh();

    console.log('Dashboard initialized successfully');
}

/**
 * Set up all event listeners
 */
function setupEventListeners() {
    // Refresh button
    refreshBtn.addEventListener('click', () => {
        loadDashboard();
    });

    // Filter controls
    scoreFilter.addEventListener('input', (e) => {
        scoreValue.textContent = e.target.value;
    });

    applyFiltersBtn.addEventListener('click', () => {
        applyFilters();
    });

    clearFiltersBtn.addEventListener('click', () => {
        clearFilters();
    });

    // Pagination
    prevPage.addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            renderAlertsTable();
        }
    });

    nextPage.addEventListener('click', () => {
        const totalPages = Math.ceil(filteredAlerts.length / ALERTS_PER_PAGE);
        if (currentPage < totalPages) {
            currentPage++;
            renderAlertsTable();
        }
    });

    // Export buttons
    exportJsonBtn.addEventListener('click', exportToJSON);
    exportCsvBtn.addEventListener('click', exportToCSV);

    // Modal close
    modalClose.addEventListener('click', closeModal);
    alertModal.addEventListener('click', (e) => {
        if (e.target === alertModal) {
            closeModal();
        }
    });

    // Table sorting
    document.querySelectorAll('.sortable').forEach(th => {
        th.addEventListener('click', () => {
            const column = th.dataset.sort;
            if (sortColumn === column) {
                sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                sortColumn = column;
                sortDirection = 'desc';
            }
            sortAlerts();
            renderAlertsTable();
        });
    });
}

/**
 * Load all dashboard data
 */
async function loadDashboard() {
    try {
        showLoading();

        // Fetch health status
        await fetchHealthStatus();

        // Fetch statistics
        await fetchStats();

        // Fetch alerts
        await fetchAlerts();

        // Apply filters and render
        applyFilters();

        // Update last updated time
        updateLastUpdated();

    } catch (error) {
        console.error('Error loading dashboard:', error);
        showError('Failed to load dashboard data');
        updateStatus(false);
    }
}

/**
 * Fetch health status from API
 */
async function fetchHealthStatus() {
    try {
        const response = await fetch(`${API_BASE_URL}/health`);
        const data = await response.json();

        if (data.status === 'healthy') {
            updateStatus(true);
        } else {
            updateStatus(false);
        }
    } catch (error) {
        console.error('Health check failed:', error);
        updateStatus(false);
    }
}

/**
 * Fetch statistics from API
 */
async function fetchStats() {
    const response = await fetch(`${API_BASE_URL}/stats`);
    if (!response.ok) {
        throw new Error('Failed to fetch statistics');
    }

    const data = await response.json();
    renderStatistics(data);
}

/**
 * Fetch alerts from API
 */
async function fetchAlerts() {
    const response = await fetch(`${API_BASE_URL}/alerts?limit=1000`);
    if (!response.ok) {
        throw new Error('Failed to fetch alerts');
    }

    const data = await response.json();
    currentAlerts = data.alerts || [];
}

/**
 * Fetch single alert details
 */
async function fetchAlertDetails(alertId) {
    const response = await fetch(`${API_BASE_URL}/alerts/${alertId}`);
    if (!response.ok) {
        throw new Error('Failed to fetch alert details');
    }

    return await response.json();
}

/**
 * Render statistics cards and charts
 */
function renderStatistics(data) {
    const alerts = data.alerts;

    // Update stat cards
    statTotal.textContent = alerts.total_alerts || 0;
    statCritical.textContent = alerts.by_severity.critical || 0;
    statHigh.textContent = alerts.by_severity.high || 0;
    statMedium.textContent = alerts.by_severity.medium || 0;
    statLow.textContent = alerts.by_severity.low || 0;

    // Update header badge
    totalAlertsBadge.textContent = alerts.total_alerts || 0;

    // Render charts
    renderScoreChart(alerts.score_distribution);
    renderPlatformChart(alerts.by_platform);
}

/**
 * Render score distribution chart
 */
function renderScoreChart(distribution) {
    const chartContainer = document.getElementById('scoreChart');

    if (!distribution || Object.keys(distribution).length === 0) {
        chartContainer.innerHTML = '<p style="text-align: center; color: #888;">No data available</p>';
        return;
    }

    // Create simple bar chart
    const ranges = ['0-25', '26-50', '51-75', '76-100', '101-125', '126-150'];
    const counts = ranges.map(range => distribution[range] || 0);
    const maxCount = Math.max(...counts, 1);

    let html = '<div class="simple-chart">';

    ranges.forEach((range, index) => {
        const count = counts[index];
        const percentage = (count / maxCount) * 100;

        html += `
            <div class="chart-bar-wrapper">
                <div class="chart-bar-label">${range}</div>
                <div class="chart-bar-container">
                    <div class="chart-bar" style="width: ${percentage}%"></div>
                    <span class="chart-bar-value">${count}</span>
                </div>
            </div>
        `;
    });

    html += '</div>';
    chartContainer.innerHTML = html;
}

/**
 * Render platform distribution chart
 */
function renderPlatformChart(platforms) {
    const chartContainer = document.getElementById('platformChart');

    if (!platforms || Object.keys(platforms).length === 0) {
        chartContainer.innerHTML = '<p style="text-align: center; color: #888;">No data available</p>';
        return;
    }

    const total = Object.values(platforms).reduce((sum, val) => sum + val, 0);

    let html = '<div class="simple-chart">';

    Object.entries(platforms).forEach(([platform, count]) => {
        const percentage = total > 0 ? ((count / total) * 100).toFixed(1) : 0;

        html += `
            <div class="chart-bar-wrapper">
                <div class="chart-bar-label">${platform}</div>
                <div class="chart-bar-container">
                    <div class="chart-bar" style="width: ${percentage}%"></div>
                    <span class="chart-bar-value">${count} (${percentage}%)</span>
                </div>
            </div>
        `;
    });

    html += '</div>';
    chartContainer.innerHTML = html;
}

/**
 * Apply filters to alerts
 */
function applyFilters() {
    const severity = severityFilter.value;
    const platform = platformFilter.value;
    const minScore = parseInt(scoreFilter.value);
    const timeRange = timeFilter.value;

    filteredAlerts = currentAlerts.filter(alert => {
        // Severity filter
        if (severity && alert.severity !== severity) {
            return false;
        }

        // Platform filter
        if (platform && alert.platform !== platform) {
            return false;
        }

        // Score filter
        if (alert.score < minScore) {
            return false;
        }

        // Time range filter
        if (timeRange !== 'all') {
            const hours = parseInt(timeRange);
            const alertTime = new Date(alert.timestamp);
            const cutoffTime = new Date(Date.now() - (hours * 60 * 60 * 1000));

            if (alertTime < cutoffTime) {
                return false;
            }
        }

        return true;
    });

    // Reset to first page
    currentPage = 1;

    // Sort and render
    sortAlerts();
    renderAlertsTable();
}

/**
 * Clear all filters
 */
function clearFilters() {
    severityFilter.value = '';
    platformFilter.value = '';
    scoreFilter.value = '0';
    scoreValue.textContent = '0';
    timeFilter.value = '24';

    applyFilters();
}

/**
 * Sort alerts based on current sort column and direction
 */
function sortAlerts() {
    filteredAlerts.sort((a, b) => {
        let aVal = a[sortColumn];
        let bVal = b[sortColumn];

        // Handle different data types
        if (sortColumn === 'timestamp') {
            aVal = new Date(aVal).getTime();
            bVal = new Date(bVal).getTime();
        } else if (sortColumn === 'score') {
            aVal = parseInt(aVal);
            bVal = parseInt(bVal);
        } else if (sortColumn === 'severity') {
            const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
            aVal = severityOrder[aVal] || 0;
            bVal = severityOrder[bVal] || 0;
        }

        if (sortDirection === 'asc') {
            return aVal > bVal ? 1 : -1;
        } else {
            return aVal < bVal ? 1 : -1;
        }
    });
}

/**
 * Render alerts table with pagination
 */
function renderAlertsTable() {
    // Calculate pagination
    const totalPages = Math.ceil(filteredAlerts.length / ALERTS_PER_PAGE);
    const startIndex = (currentPage - 1) * ALERTS_PER_PAGE;
    const endIndex = startIndex + ALERTS_PER_PAGE;
    const pageAlerts = filteredAlerts.slice(startIndex, endIndex);

    // Update alerts count
    alertsCount.textContent = `${filteredAlerts.length} alert${filteredAlerts.length !== 1 ? 's' : ''}`;

    // Update pagination info
    pageInfo.textContent = `Page ${currentPage} of ${totalPages || 1}`;
    prevPage.disabled = currentPage === 1;
    nextPage.disabled = currentPage === totalPages || totalPages === 0;

    // Render table rows
    if (pageAlerts.length === 0) {
        alertsTableBody.innerHTML = '<tr class="no-data-row"><td colspan="7">No alerts found</td></tr>';
        return;
    }

    let html = '';
    pageAlerts.forEach(alert => {
        const timestamp = formatTimestamp(alert.timestamp);
        const command = truncate(alert.command_line || 'N/A', 60);

        html += `
            <tr class="alert-row" data-alert-id="${alert.id}">
                <td>${timestamp}</td>
                <td><span class="severity-badge severity-${alert.severity}">${alert.severity}</span></td>
                <td><span class="score-badge">${alert.score}</span></td>
                <td>${alert.rule_name}</td>
                <td>${alert.platform}</td>
                <td>${alert.process_name || 'N/A'}</td>
                <td title="${alert.command_line || 'N/A'}">${command}</td>
            </tr>
        `;
    });

    alertsTableBody.innerHTML = html;

    // Add click handlers to rows
    document.querySelectorAll('.alert-row').forEach(row => {
        row.addEventListener('click', () => {
            const alertId = row.dataset.alertId;
            showAlertModal(alertId);
        });
    });
}

/**
 * Show alert details in modal
 */
async function showAlertModal(alertId) {
    try {
        const alert = await fetchAlertDetails(alertId);

        modalTitle.textContent = `Alert #${alert.id} - ${alert.rule_name}`;

        let html = `
            <div class="modal-section">
                <h3>Basic Information</h3>
                <table class="detail-table">
                    <tr><th>Alert ID:</th><td>${alert.id}</td></tr>
                    <tr><th>Rule ID:</th><td>${alert.rule_id}</td></tr>
                    <tr><th>Severity:</th><td><span class="severity-badge severity-${alert.severity}">${alert.severity}</span></td></tr>
                    <tr><th>Score:</th><td><span class="score-badge">${alert.score}</span></td></tr>
                    <tr><th>Timestamp:</th><td>${formatTimestamp(alert.timestamp)}</td></tr>
                    <tr><th>Platform:</th><td>${alert.platform}</td></tr>
                </table>
            </div>

            <div class="modal-section">
                <h3>Process Information</h3>
                <table class="detail-table">
                    <tr><th>Process Name:</th><td>${alert.process_name || 'N/A'}</td></tr>
                    <tr><th>Process ID:</th><td>${alert.process_id || 'N/A'}</td></tr>
                    <tr><th>Parent Process:</th><td>${alert.parent_process || 'N/A'}</td></tr>
                    <tr><th>User:</th><td>${alert.user || 'N/A'}</td></tr>
                    <tr><th>Working Directory:</th><td>${alert.working_directory || 'N/A'}</td></tr>
                </table>
            </div>

            <div class="modal-section">
                <h3>Command Line</h3>
                <pre class="command-line">${alert.command_line || 'N/A'}</pre>
            </div>

            <div class="modal-section">
                <h3>Detection Details</h3>
                <table class="detail-table">
                    <tr><th>Description:</th><td>${alert.description}</td></tr>
                </table>
            </div>
        `;

        if (alert.mitre_attack && alert.mitre_attack.length > 0) {
            html += `
                <div class="modal-section">
                    <h3>MITRE ATT&CK</h3>
                    <div class="mitre-techniques">
                        ${alert.mitre_attack.map(t => `<span class="mitre-badge">${t}</span>`).join(' ')}
                    </div>
                </div>
            `;
        }

        if (alert.response && alert.response.length > 0) {
            html += `
                <div class="modal-section">
                    <h3>Recommended Response</h3>
                    <ul class="response-list">
                        ${alert.response.map(r => `<li>${r}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        modalBody.innerHTML = html;
        alertModal.classList.add('show');

    } catch (error) {
        console.error('Error loading alert details:', error);
        showError('Failed to load alert details');
    }
}

/**
 * Close the modal
 */
function closeModal() {
    alertModal.classList.remove('show');
}

/**
 * Export alerts to JSON
 */
function exportToJSON() {
    const data = JSON.stringify(filteredAlerts, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    downloadFile(blob, 'lotl-alerts.json');
}

/**
 * Export alerts to CSV
 */
function exportToCSV() {
    if (filteredAlerts.length === 0) {
        showError('No alerts to export');
        return;
    }

    // CSV headers
    const headers = ['ID', 'Timestamp', 'Severity', 'Score', 'Rule ID', 'Rule Name', 'Platform', 'Process', 'User', 'Command Line'];

    // CSV rows
    const rows = filteredAlerts.map(alert => [
        alert.id,
        alert.timestamp,
        alert.severity,
        alert.score,
        alert.rule_id,
        alert.rule_name,
        alert.platform,
        alert.process_name || '',
        alert.user || '',
        `"${(alert.command_line || '').replace(/"/g, '""')}"`
    ]);

    // Build CSV
    const csv = [
        headers.join(','),
        ...rows.map(row => row.join(','))
    ].join('\n');

    const blob = new Blob([csv], { type: 'text/csv' });
    downloadFile(blob, 'lotl-alerts.csv');
}

/**
 * Download a file
 */
function downloadFile(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * Update connection status indicator
 */
function updateStatus(healthy) {
    if (healthy) {
        statusDot.className = 'status-dot status-connected';
        statusText.textContent = 'Connected';
    } else {
        statusDot.className = 'status-dot status-disconnected';
        statusText.textContent = 'Disconnected';
    }
}

/**
 * Update last updated timestamp
 */
function updateLastUpdated() {
    const now = new Date();
    lastUpdated.textContent = now.toLocaleTimeString();
}

/**
 * Show loading state
 */
function showLoading() {
    alertsTableBody.innerHTML = '<tr class="loading-row"><td colspan="7">Loading alerts...</td></tr>';
}

/**
 * Show error toast
 */
function showError(message) {
    toastMessage.textContent = message;
    errorToast.classList.add('show');

    setTimeout(() => {
        errorToast.classList.remove('show');
    }, 5000);
}

/**
 * Start auto-refresh timer
 */
function startAutoRefresh() {
    if (autoRefreshTimer) {
        clearInterval(autoRefreshTimer);
    }

    autoRefreshTimer = setInterval(() => {
        console.log('Auto-refreshing dashboard...');
        loadDashboard();
    }, REFRESH_INTERVAL);
}

/**
 * Format timestamp for display
 */
function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;

    // Less than 1 minute
    if (diff < 60000) {
        return 'Just now';
    }

    // Less than 1 hour
    if (diff < 3600000) {
        const minutes = Math.floor(diff / 60000);
        return `${minutes}m ago`;
    }

    // Less than 24 hours
    if (diff < 86400000) {
        const hours = Math.floor(diff / 3600000);
        return `${hours}h ago`;
    }

    // More than 24 hours - show date and time
    return date.toLocaleString();
}

/**
 * Truncate string to specified length
 */
function truncate(str, length) {
    if (str.length <= length) {
        return str;
    }
    return str.substring(0, length) + '...';
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
