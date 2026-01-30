// JavaScript for Integration Services UI (SSRF Testing)

function testWidgetEndpoint(url, inputId, resultId) {
    const scriptCode = document.getElementById(inputId).value;
    const resultContainer = document.getElementById(resultId);
    
    resultContainer.innerHTML = '<div class="loading">Testing endpoint...</div>';
    
    fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'scriptCode=' + encodeURIComponent(scriptCode)
    })
    .then(response => response.json())
    .then(data => {
        resultContainer.innerHTML = `
            <div class="result-box ${data.valid || data.success ? 'success' : 'error'}">
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

function testServiceEndpoint(url, inputId, resultId) {
    const serviceUrl = document.getElementById(inputId).value;
    const resultContainer = document.getElementById(resultId);
    
    resultContainer.innerHTML = '<div class="loading">Testing endpoint...</div>';
    
    const fullUrl = `${url}?serviceUrl=${encodeURIComponent(serviceUrl)}`;
    
    fetch(fullUrl)
    .then(response => response.json())
    .then(data => {
        resultContainer.innerHTML = `
            <div class="result-box ${data.success ? 'success' : 'error'}">
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

function fillWidgetPayload(payload) {
    document.getElementById('widget-script').value = payload;
    document.getElementById('widget-script-secure').value = payload;
}

function fillServicePayload(payload) {
    document.getElementById('service-url').value = payload;
    document.getElementById('service-url-secure').value = payload;
}

function clearAllFields() {
    document.getElementById('widget-script').value = '<script src="http://localhost:8081/api/integration/health"></script>';
    document.getElementById('widget-script-secure').value = '<script src="http://localhost:8081/api/integration/health"></script>';
    document.getElementById('service-url').value = 'http://localhost:8081/api/integration/health';
    document.getElementById('service-url-secure').value = 'http://localhost:8081/api/integration/health';
    
    document.querySelectorAll('.result-container').forEach(container => {
        container.innerHTML = '';
    });
}

document.addEventListener('DOMContentLoaded', function() {
    console.log('Integration Services UI loaded successfully');
});
