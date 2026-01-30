// JavaScript for Notification Services UI (XXE Testing)

const normalXML = `<?xml version="1.0" encoding="UTF-8"?>
<xml>
  <ToUserName>user123</ToUserName>
  <FromUserName>sender456</FromUserName>
  <MsgType>event</MsgType>
  <Event>subscribe</Event>
</xml>`;

const xxeFilePayload = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<xml>
  <ToUserName>&xxe;</ToUserName>
  <FromUserName>attacker</FromUserName>
  <MsgType>attack</MsgType>
</xml>`;

function testWebhookEndpoint(url, inputId, resultId) {
    const xmlContent = document.getElementById(inputId).value;
    const resultContainer = document.getElementById(resultId);
    
    resultContainer.innerHTML = '<div class="loading">Processing webhook...</div>';
    
    fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/xml',
        },
        body: xmlContent
    })
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

function fillXMLPayload(payload) {
    document.getElementById('webhook-xml').value = payload;
    document.getElementById('webhook-xml-secure').value = payload;
}

function clearAllFields() {
    document.querySelectorAll('textarea').forEach(textarea => {
        textarea.value = normalXML;
    });
    document.querySelectorAll('.result-container').forEach(container => {
        container.innerHTML = '';
    });
}

document.addEventListener('DOMContentLoaded', function() {
    console.log('Notification Services UI loaded successfully');
});
