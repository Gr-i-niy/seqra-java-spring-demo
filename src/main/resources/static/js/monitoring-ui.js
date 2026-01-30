// JavaScript for Monitoring Services UI (SQL Injection Testing)

const DEFAULT_MONITOR_ID = '123';
const DEFAULT_METRIC_FULL = 'linux.cpu.usage';
const DEFAULT_HISTORY = '6h';
const DEFAULT_INSTANCE = 'server1';
const DEFAULT_MONITOR_NAME = 'Production Server';

function testMetricsEndpoint(url, isSecure, resultId) {
    const suffix = isSecure ? '-secure' : '';
    const monitorId = document.getElementById('monitor-id' + suffix).value;
    const metricFull = document.getElementById('metric-full' + suffix).value;
    const history = document.getElementById('history' + suffix).value;
    const instance = document.getElementById('instance' + suffix).value;

    const resultContainer = document.getElementById(resultId);
    resultContainer.innerHTML = '<div class="loading">Querying metrics...</div>';

    let fullUrl = `${url}?monitorId=${encodeURIComponent(monitorId)}&metricFull=${encodeURIComponent(metricFull)}&history=${encodeURIComponent(history)}`;
    if (instance) {
        fullUrl += `&instance=${encodeURIComponent(instance)}`;
    }

    fetch(fullUrl)
    .then(response => response.json())
    .then(data => {
        const hasData = Object.keys(data).length > 0 && !data.error;
        resultContainer.innerHTML = `
            <div class="result-box ${hasData ? 'success' : 'error'}">
                <h4>Response:</h4>
                <pre>${JSON.stringify(data, null, 2)}</pre>
            </div>
        `;
    })
    .catch(error => {
        resultContainer.innerHTML = `
            <div class="result-box error">
                <h4>Error:</h4>
                <pre>${error.message}</pre>
            </div>
        `;
    });
}

function verifyMonitor(url, inputId, resultId) {
    const monitorName = document.getElementById(inputId).value;
    const resultContainer = document.getElementById(resultId);

    resultContainer.innerHTML = '<div class="loading">Verifying monitor...</div>';

    const startTime = performance.now();

    fetch(`${url}?monitorName=${encodeURIComponent(monitorName)}`)
    .then(response => response.json())
    .then(data => {
        const endTime = performance.now();
        const duration = Math.round(endTime - startTime);

        const isVerified = data.verified === true;
        resultContainer.innerHTML = `
            <div class="result-box ${isVerified ? 'success' : 'error'}">
                <h4>Response (${duration}ms):</h4>
                <pre>${JSON.stringify(data, null, 2)}</pre>
            </div>
        `;
    })
    .catch(error => {
        const endTime = performance.now();
        const duration = Math.round(endTime - startTime);

        resultContainer.innerHTML = `
            <div class="result-box error">
                <h4>Error (${duration}ms):</h4>
                <pre>${error.message}</pre>
            </div>
        `;
    });
}

function fillInstancePayload(payload) {
    document.getElementById('instance').value = payload;
    document.getElementById('instance-secure').value = payload;
}

function fillInstancePayloadFromElement(elementId) {
    const payload = document.getElementById(elementId).textContent;
    fillInstancePayload(payload);
}

function fillMonitorPayload(payload) {
    document.getElementById('monitor-name').value = payload;
    document.getElementById('monitor-name-secure').value = payload;
}

function fillMonitorPayloadFromElement(elementId) {
    const payload = document.getElementById(elementId).textContent;
    fillMonitorPayload(payload);
}

function clearAllFields() {
    document.getElementById('monitor-id').value = DEFAULT_MONITOR_ID;
    document.getElementById('monitor-id-secure').value = DEFAULT_MONITOR_ID;
    document.getElementById('metric-full').value = DEFAULT_METRIC_FULL;
    document.getElementById('metric-full-secure').value = DEFAULT_METRIC_FULL;
    document.getElementById('history').value = DEFAULT_HISTORY;
    document.getElementById('history-secure').value = DEFAULT_HISTORY;
    document.getElementById('instance').value = DEFAULT_INSTANCE;
    document.getElementById('instance-secure').value = DEFAULT_INSTANCE;
    document.getElementById('monitor-name').value = DEFAULT_MONITOR_NAME;
    document.getElementById('monitor-name-secure').value = DEFAULT_MONITOR_NAME;

    document.querySelectorAll('.result-container').forEach(container => {
        container.innerHTML = '';
    });
}

document.addEventListener('DOMContentLoaded', function() {
    console.log('Monitoring Services UI loaded successfully');
});
