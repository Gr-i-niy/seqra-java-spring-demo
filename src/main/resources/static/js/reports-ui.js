// JavaScript for Report Generation UI (Command Injection Testing)

const DEFAULT_HOSTNAME = 'localhost';

function checkNetwork(url, inputId, resultId) {
    const hostname = document.getElementById(inputId).value;
    const resultContainer = document.getElementById(resultId);

    resultContainer.innerHTML = '<div class="loading">Running network check...</div>';

    const fullUrl = `${url}?hostname=${encodeURIComponent(hostname)}`;

    fetch(fullUrl)
    .then(response => response.json())
    .then(data => {
        const isSuccess = data.success === true;
        resultContainer.innerHTML = `
            <div class="result-box ${isSuccess ? 'success' : 'error'}">
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

function fillHostnamePayload(payload) {
    document.getElementById('hostname').value = payload;
    document.getElementById('hostname-secure').value = payload;
}

function fillHostnamePayloadFromElement(elementId) {
    const payload = document.getElementById(elementId).textContent;
    fillHostnamePayload(payload);
}

function clearAllFields() {
    document.getElementById('hostname').value = DEFAULT_HOSTNAME;
    document.getElementById('hostname-secure').value = DEFAULT_HOSTNAME;

    document.querySelectorAll('.result-container').forEach(container => {
        container.innerHTML = '';
    });
}

document.addEventListener('DOMContentLoaded', function() {
    console.log('Report Generation UI loaded successfully');
});
