// JavaScript for Monitoring Services UI (SQL Injection Testing)

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

function fillInstancePayload(payload) {
    document.getElementById('instance').value = payload;
    document.getElementById('instance-secure').value = payload;
}

function clearAllFields() {
    document.getElementById('monitor-id').value = '123';
    document.getElementById('monitor-id-secure').value = '123';
    document.getElementById('metric-full').value = 'linux.cpu.usage';
    document.getElementById('metric-full-secure').value = 'linux.cpu.usage';
    document.getElementById('history').value = '6h';
    document.getElementById('history-secure').value = '6h';
    document.getElementById('instance').value = 'server1';
    document.getElementById('instance-secure').value = 'server1';
    
    document.querySelectorAll('.result-container').forEach(container => {
        container.innerHTML = '';
    });
}

document.addEventListener('DOMContentLoaded', function() {
    console.log('Monitoring Services UI loaded successfully');
});
