// JavaScript for Alert Definitions UI (Path Traversal Testing)

const DEFAULT_FILENAME = 'alert-cpu-high.yml';
const DEFAULT_ALERT_NAME = 'cpu-high';
const DEFAULT_SAVE_FILENAME = 'alert-custom.yml';
const DEFAULT_SAVE_NAME = 'custom-alert';
const DEFAULT_CONTENT = 'name: Custom Alert\ntype: threshold\nmetric: system.load.1\ncondition: "> 5"\nseverity: warning';

function getAlert(url, inputId, resultId) {
    const filename = document.getElementById(inputId).value;
    const resultContainer = document.getElementById(resultId);

    resultContainer.innerHTML = '<div class="loading">Fetching alert definition...</div>';

    const fullUrl = `${url}?filename=${encodeURIComponent(filename)}`;

    fetch(fullUrl)
    .then(response => response.json())
    .then(data => {
        const hasContent = data.content !== undefined;
        resultContainer.innerHTML = `
            <div class="result-box ${hasContent ? 'success' : 'error'}">
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

function getAlertSecure(url, inputId, resultId) {
    const alertName = document.getElementById(inputId).value;
    const resultContainer = document.getElementById(resultId);

    resultContainer.innerHTML = '<div class="loading">Fetching alert definition...</div>';

    const fullUrl = `${url}?alertName=${encodeURIComponent(alertName)}`;

    fetch(fullUrl)
    .then(response => response.json())
    .then(data => {
        const hasContent = data.content !== undefined;
        resultContainer.innerHTML = `
            <div class="result-box ${hasContent ? 'success' : 'error'}">
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

function saveAlert(url, filenameInputId, contentInputId, resultId) {
    const filename = document.getElementById(filenameInputId).value;
    const content = document.getElementById(contentInputId).value;
    const resultContainer = document.getElementById(resultId);

    resultContainer.innerHTML = '<div class="loading">Saving alert definition...</div>';

    fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `filename=${encodeURIComponent(filename)}&content=${encodeURIComponent(content)}`
    })
    .then(response => response.json())
    .then(data => {
        const isSuccess = data.status === 'saved';
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

function saveAlertSecure(url, nameInputId, contentInputId, resultId) {
    const alertName = document.getElementById(nameInputId).value;
    const content = document.getElementById(contentInputId).value;
    const resultContainer = document.getElementById(resultId);

    resultContainer.innerHTML = '<div class="loading">Saving alert definition...</div>';

    fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `alertName=${encodeURIComponent(alertName)}&content=${encodeURIComponent(content)}`
    })
    .then(response => response.json())
    .then(data => {
        const isSuccess = data.status === 'saved';
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

function fillReadPayload(payload) {
    document.getElementById('alert-filename').value = payload;
    document.getElementById('alert-name-secure').value = payload;
}

function fillWritePayload(filename, content) {
    document.getElementById('save-filename').value = filename;
    document.getElementById('save-name-secure').value = filename;
    document.getElementById('save-content').value = content;
    document.getElementById('save-content-secure').value = content;
}

function clearAllFields() {
    document.getElementById('alert-filename').value = DEFAULT_FILENAME;
    document.getElementById('alert-name-secure').value = DEFAULT_ALERT_NAME;
    document.getElementById('save-filename').value = DEFAULT_SAVE_FILENAME;
    document.getElementById('save-name-secure').value = DEFAULT_SAVE_NAME;
    document.getElementById('save-content').value = DEFAULT_CONTENT;
    document.getElementById('save-content-secure').value = DEFAULT_CONTENT;

    document.querySelectorAll('.result-container').forEach(container => {
        container.innerHTML = '';
    });
}

document.addEventListener('DOMContentLoaded', function() {
    console.log('Alert Definitions UI loaded successfully');
});
