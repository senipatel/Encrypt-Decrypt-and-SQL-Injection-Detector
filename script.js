// Tab Switching
function showTab(tabId) {
    document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    document.querySelector(`.tab[onclick="showTab('${tabId}')"]`).classList.add('active');
    document.getElementById(tabId).classList.add('active');
}

// Encrypt/Decrypt Functions
function toggleKeyInput() {
    const method = document.getElementById('method').value;
    document.getElementById('shiftKey').style.display = method === 'caesar' ? 'block' : 'none';
}

function base64Encrypt(text) { return btoa(text); }
function base64Decrypt(text) {
    try { return atob(text); } catch (e) { return null; }
}

function caesarCipher(text, shift, decrypt = false) {
    if (decrypt) shift = -shift;
    return text.split('').map(char => {
        const code = char.charCodeAt(0);
        if (code >= 65 && code <= 90) return String.fromCharCode((code - 65 + shift + 26) % 26 + 65);
        if (code >= 97 && code <= 122) return String.fromCharCode((code - 97 + shift + 26) % 26 + 97);
        return char;
    }).join('');
}

function md5(text) {
    function rotateLeft(x, n) { return (x << n) | (x >>> (32 - n)); }
    const K = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee];
    let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476;
    const utf8 = unescape(encodeURIComponent(text));
    return [h0, h1, h2, h3].map(n => n.toString(16).padStart(8, '0')).join('');
}

function sha256(text) {
    function rightRotate(x, n) { return (x >>> n) | (x << (32 - n)); }
    const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5];
    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a,
        h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    const utf8 = unescape(encodeURIComponent(text));
    return [h0, h1, h2, h3, h4, h5, h6, h7].map(n => n.toString(16).padStart(8, '0')).join('');
}

function processInput(isDecrypt = false) {
    const inputText = document.getElementById('encryptInput').value.trim();
    const method = document.getElementById('method').value;
    const resultDiv = document.getElementById('encryptResult');
    resultDiv.innerHTML = ''; resultDiv.className = '';

    if (!inputText) {
        resultDiv.className = 'error';
        resultDiv.innerHTML = 'Error: Please enter some text.';
        return;
    }

    let result;
    if (method === 'base64') {
        result = isDecrypt ? base64Decrypt(inputText) : base64Encrypt(inputText);
        if (isDecrypt && result === null) {
            resultDiv.className = 'error';
            resultDiv.innerHTML = 'Error: Invalid Base64 string.';
            return;
        }
    } else if (method === 'caesar') {
        const shift = parseInt(document.getElementById('shiftKey').value);
        if (isNaN(shift) || shift < 1 || shift > 25) {
            resultDiv.className = 'error';
            resultDiv.innerHTML = 'Error: Shift must be a number between 1 and 25.';
            return;
        }
        result = caesarCipher(inputText, shift, isDecrypt);
    } else if (method === 'md5') {
        if (isDecrypt) {
            resultDiv.className = 'error';
            resultDiv.innerHTML = 'Error: MD5 is a one-way hash function and cannot be decrypted.';
            return;
        }
        result = md5(inputText);
    } else if (method === 'sha256') {
        if (isDecrypt) {
            resultDiv.className = 'error';
            resultDiv.innerHTML = 'Error: SHA-256 is a one-way hash function and cannot be decrypted.';
            return;
        }
        result = sha256(inputText);
    }
    resultDiv.innerHTML = result;
}

function encrypt() { processInput(false); }
function decrypt() { processInput(true); }

// SQL Injection Detector Functions
function updatePlaceholder() {
    const mode = document.getElementById('mode').value;
    document.getElementById('sqlInput').placeholder = mode === 'query'
        ? "Enter a SQL query (e.g., SELECT * FROM users WHERE id = '1' OR '1'='1')"
        : "Enter form input (e.g., admin' --)";
}

function detectSQLInjection(input, isFormMode = false) {
    const patterns = [
        { pattern: /'?\s*OR\s*['"]?1['"]?\s*=\s*['"]?1['"]?/i, message: "Tautology detected (e.g., '1'='1'): Can bypass conditions." },
        { pattern: /--|\/\*|\*\/|#/i, message: "SQL comment detected (e.g., --, #): May truncate query." },
        { pattern: /UNION\s+(ALL\s+)?SELECT/i, message: "UNION statement detected: Could extract additional data." },
        { pattern: /;/i, message: "Semicolon detected: May allow multiple queries." },
        { pattern: /['"]/g, message: "Unescaped quotes detected: Could break query structure." }
    ];

    let issues = [];
    patterns.forEach(check => {
        if (check.pattern.test(input)) issues.push(check.message);
    });

    if (isFormMode && input) {
        const simulatedQuery = `SELECT * FROM users WHERE username = '${input}'`;
        patterns.forEach(check => {
            if (check.pattern.test(simulatedQuery) && !issues.includes(check.message))
                issues.push(check.message + " (Simulated in query)");
        });
    }
    return issues;
}

function analyzeInput() {
    const inputText = document.getElementById('sqlInput').value.trim();
    const mode = document.getElementById('mode').value;
    const resultDiv = document.getElementById('sqlResult');
    resultDiv.innerHTML = ''; resultDiv.className = '';

    if (!inputText) {
        resultDiv.className = 'error';
        resultDiv.innerHTML = 'Error: Please enter some text to analyze.';
        return;
    }

    const isFormMode = mode === 'form';
    const issues = detectSQLInjection(inputText, isFormMode);

    resultDiv.className = issues.length > 0 ? 'warning' : 'safe';
    if (issues.length > 0) {
        resultDiv.innerHTML = '<strong>Potential SQL Injection Detected:</strong><ul>' +
            issues.map(issue => `<li>${issue}</li>`).join('') +
            '</ul><p><strong>Suggestion:</strong> Use parameterized queries instead of direct concatenation.</p>';
    } else {
        resultDiv.innerHTML = 'No Issues Found: Input appears safe from common SQL injection patterns.';
    }
}

// Initialize
toggleKeyInput();
updatePlaceholder();