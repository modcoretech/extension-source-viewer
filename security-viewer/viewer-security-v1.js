// --- CONFIGURATION & PATTERNS ---

// Regex for Secrets Detection
const SECRET_PATTERNS = [
    { name: 'AWS Access Key', regex: /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g, severity: 'critical' },
    { name: 'Google API Key', regex: /AIza[0-9A-Za-z\\-_]{35}/g, severity: 'high' },
    { name: 'Generic Private Key', regex: /-----BEGIN [A-Z]+ PRIVATE KEY-----/g, severity: 'critical' },
    { name: 'Slack Token', regex: /xox[baprs]-([0-9a-zA-Z]{10,48})/g, severity: 'high' },
    { name: 'Stripe API Key', regex: /(?:r|s)k_(?:test|live)_[0-9a-zA-Z]{24}/g, severity: 'high' },
    { name: 'Hardcoded Email', regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, severity: 'low' },
    { name: 'IP Address (IPv4)', regex: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, severity: 'medium' }
];

// Dangerous JS Functions (for AST Analysis)
const DANGEROUS_SINKS = {
    'eval': { severity: 'critical', desc: 'Arbitrary code execution via eval()' },
    'setTimeout': { severity: 'medium', desc: 'Potential code execution if string used' },
    'setInterval': { severity: 'medium', desc: 'Potential code execution if string used' },
    'document.write': { severity: 'high', desc: 'DOM XSS Risk' },
    'innerHTML': { severity: 'high', desc: 'DOM XSS Risk' },
    'outerHTML': { severity: 'high', desc: 'DOM XSS Risk' },
    'chrome.cookies.getAll': { severity: 'high', desc: 'Accesses all browser cookies' },
    'chrome.webRequest': { severity: 'medium', desc: 'Intercepts network traffic' }
};

// --- STATE ---
let zip = null;
let findings = [];
let fileMap = {};
let riskScore = 0;
let chartInstance = null;

// --- INITIALIZATION ---
document.getElementById('fileInput').addEventListener('change', handleFileUpload);
document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.target));
});

// --- CORE LOGIC ---

async function handleFileUpload(e) {
    const file = e.target.files[0];
    if (!file) return;

    resetState();
    toggleLoading(true);

    try {
        const zipData = await JSZip.loadAsync(file);
        zip = zipData;
        
        // 1. Map Files
        for (const [path, fileObj] of Object.entries(zip.files)) {
            if (!fileObj.dir) fileMap[path] = fileObj;
        }

        // 2. Run Engines
        await runManifestEngine();
        await runCodeEngine(); // Includes Secrets & AST
        
        // 3. Render Results
        calculateScore();
        renderDashboard();
        renderManifest();
        renderSecrets();
        renderDangerous();
        renderFileTree();
        
        document.getElementById('emptyState').classList.add('hidden');
        document.getElementById('view-dashboard').classList.remove('hidden');

    } catch (err) {
        console.error(err);
        alert('Error parsing file: ' + err.message);
    } finally {
        toggleLoading(false);
    }
}

function resetState() {
    findings = [];
    fileMap = {};
    riskScore = 0;
    document.querySelectorAll('.view-section').forEach(el => el.classList.add('hidden'));
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active', 'bg-gray-700', 'text-white'));
    document.querySelector('[data-target="dashboard"]').classList.add('active', 'bg-gray-700', 'text-white');
}

// --- ENGINE 1: MANIFEST ANALYSIS ---
async function runManifestEngine() {
    const manifestFile = fileMap['manifest.json'];
    if (!manifestFile) {
        addFinding('manifest', 'critical', 'Missing manifest.json file');
        return;
    }

    try {
        const content = await manifestFile.async('string');
        const manifest = JSON.parse(content);
        
        // MV Check
        if (manifest.manifest_version !== 3) {
            addFinding('manifest', 'medium', `Uses Manifest V${manifest.manifest_version} (V3 is recommended)`);
        }

        // Permissions
        const perms = manifest.permissions || [];
        if (perms.includes('<all_urls>') || perms.includes('*://*/*') || perms.includes('http://*/*')) {
            addFinding('manifest', 'critical', 'Broad Host Permissions detected (<all_urls> or wildcards)');
        }
        if (perms.includes('cookies')) addFinding('manifest', 'high', 'Permission: Access to cookies');
        if (perms.includes('tabs')) addFinding('manifest', 'medium', 'Permission: Access to tabs/navigation');
        if (perms.includes('webRequest') && perms.includes('webRequestBlocking')) {
            addFinding('manifest', 'high', 'Permission: webRequestBlocking (Intercepts & modifies traffic)');
        }

        // CSP Check
        const csp = manifest.content_security_policy;
        if (!csp && manifest.manifest_version === 2) {
            addFinding('manifest', 'high', 'Missing Content Security Policy (MV2)');
        } else if (csp) {
            const cspStr = typeof csp === 'object' ? (csp.extension_pages || '') : csp;
            if (cspStr.includes("'unsafe-eval'")) addFinding('manifest', 'critical', "CSP allows 'unsafe-eval'");
            if (cspStr.includes("http:")) addFinding('manifest', 'high', "CSP allows insecure HTTP sources");
        }

        // Store raw for display
        document.getElementById('rawManifest').textContent = JSON.stringify(manifest, null, 2);
        hljs.highlightElement(document.getElementById('rawManifest'));

    } catch (e) {
        addFinding('manifest', 'critical', 'Invalid JSON in manifest.json');
    }
}

// --- ENGINE 2: CODE ANALYSIS (AST & SECRETS) ---
async function runCodeEngine() {
    const jsFiles = Object.keys(fileMap).filter(f => f.endsWith('.js') || f.endsWith('.json'));

    for (const path of jsFiles) {
        const content = await fileMap[path].async('string');
        
        // 2a. Secrets Scan (Regex)
        SECRET_PATTERNS.forEach(pattern => {
            const matches = content.match(pattern.regex);
            if (matches) {
                // Deduplicate matches
                [...new Set(matches)].forEach(match => {
                    const masked = match.substring(0, 4) + '...' + match.substring(match.length - 4);
                    addFinding('secrets', pattern.severity, `${pattern.name} found in ${path}: ${masked}`, path);
                });
            }
        });

        // 2b. AST Analysis (Only for JS)
        if (path.endsWith('.js')) {
            try {
                // Parse using Esprima
                const ast = esprima.parseScript(content, { range: true, loc: true, tolerant: true });
                walkAST(ast, (node) => checkNode(node, path, content));
            } catch (e) {
                console.warn(`Failed to parse ${path}:`, e.message);
                addFinding('code', 'low', `Parser failed on ${path} (Minified or modern syntax error)`);
            }
        }
    }
}

// Recursive AST Walker
function walkAST(node, callback) {
    if (!node) return;
    callback(node);
    for (const key in node) {
        if (node.hasOwnProperty(key)) {
            const child = node[key];
            if (typeof child === 'object' && child !== null) {
                if (Array.isArray(child)) {
                    child.forEach(c => walkAST(c, callback));
                } else {
                    walkAST(child, callback);
                }
            }
        }
    }
}

// Check AST Node for Red Flags
function checkNode(node, path, content) {
    if (node.type === 'CallExpression' && node.callee) {
        // Direct calls like eval()
        if (node.callee.type === 'Identifier') {
            const name = node.callee.name;
            if (DANGEROUS_SINKS[name]) {
                const line = node.loc ? node.loc.start.line : '?';
                addFinding('dangerous', DANGEROUS_SINKS[name].severity, 
                    `${DANGEROUS_SINKS[name].desc} at line ${line}`, path, line);
            }
        }
        // Member calls like chrome.cookies.getAll()
        else if (node.callee.type === 'MemberExpression') {
            const prop = node.callee.property.name;
            const obj = node.callee.object.name; // Simple case
            const fullName = `${obj}.${prop}`; // simplified
            
            if (prop === 'innerHTML' || prop === 'outerHTML') {
                 const line = node.loc ? node.loc.start.line : '?';
                 addFinding('dangerous', 'high', `Use of .innerHTML (DOM XSS Risk) at line ${line}`, path, line);
            }
        }
    }
}

// --- UTILS & RENDERERS ---

function addFinding(category, severity, message, file = null, line = null) {
    findings.push({ category, severity, message, file, line });
}

function calculateScore() {
    let score = 100;
    const weights = { critical: 25, high: 10, medium: 5, low: 1 };
    
    findings.forEach(f => {
        score -= weights[f.severity] || 0;
    });
    
    if (score < 0) score = 0;
    riskScore = score;
    
    // UI Update
    const el = document.getElementById('globalScore');
    const label = document.getElementById('globalRiskLabel');
    el.textContent = score + '/100';
    
    el.className = `text-3xl font-bold ${score > 80 ? 'text-green-500' : score > 50 ? 'text-yellow-500' : 'text-red-500'}`;
    
    if (score === 100) label.textContent = 'SAFE';
    else if (score > 80) label.textContent = 'LOW RISK';
    else if (score > 50) label.textContent = 'MODERATE RISK';
    else label.textContent = 'CRITICAL RISK';
}

function renderDashboard() {
    // 1. Chart
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    findings.forEach(f => { if(counts[f.severity] !== undefined) counts[f.severity]++ });

    const ctx = document.getElementById('riskChart').getContext('2d');
    if (chartInstance) chartInstance.destroy();
    
    chartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [counts.critical, counts.high, counts.medium, counts.low],
                backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'right', labels: { color: '#cbd5e1' } }
            }
        }
    });

    // 2. Counts
    document.getElementById('summaryManifest').textContent = findings.filter(f => f.category === 'manifest').length;
    document.getElementById('summarySecrets').textContent = findings.filter(f => f.category === 'secrets').length;
    document.getElementById('summaryCode').textContent = findings.filter(f => f.category === 'dangerous').length;
    
    // 3. Critical List
    const list = document.getElementById('criticalList');
    list.innerHTML = '';
    const criticals = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
    
    if (criticals.length === 0) {
        list.innerHTML = '<div class="text-green-500 text-sm"><i class="fa-solid fa-check"></i> No critical issues found.</div>';
    } else {
        criticals.forEach(f => {
            const div = document.createElement('div');
            div.className = `finding-item border-${f.severity === 'critical' ? 'red' : 'orange'}-500`;
            div.innerHTML = `
                <div class="flex justify-between">
                    <span class="text-${f.severity === 'critical' ? 'red' : 'orange'}-400 font-bold uppercase text-xs">${f.severity}</span>
                    <span class="text-xs text-gray-500">${f.file || 'System'}</span>
                </div>
                <div class="text-gray-200 mt-1">${f.message}</div>
            `;
            div.onclick = () => { if(f.file) openSourceFile(f.file, f.line); };
            div.style.cursor = f.file ? 'pointer' : 'default';
            list.appendChild(div);
        });
    }
}

function renderManifest() {
    const permContainer = document.getElementById('permList');
    const cspContainer = document.getElementById('cspList');
    permContainer.innerHTML = '';
    cspContainer.innerHTML = '';

    findings.filter(f => f.category === 'manifest').forEach(f => {
        const div = document.createElement('div');
        div.className = `text-sm py-1 border-b border-gray-700/50 ${f.severity === 'critical' ? 'text-red-400' : 'text-gray-300'}`;
        div.innerHTML = `<i class="fa-solid fa-circle text-[8px] mr-2"></i> ${f.message}`;
        if (f.message.includes('Permission')) permContainer.appendChild(div);
        else cspContainer.appendChild(div);
    });
}

function renderSecrets() {
    const container = document.getElementById('secretsContainer');
    container.innerHTML = '';
    
    findings.filter(f => f.category === 'secrets').forEach(f => {
        const div = document.createElement('div');
        div.className = 'bg-gray-800 p-3 rounded border border-gray-700 flex justify-between items-center group hover:border-red-500 transition';
        div.innerHTML = `
            <div>
                <div class="text-red-400 font-bold text-sm mb-1">${f.message.split(':')[0]}</div>
                <div class="text-xs text-gray-500 font-mono">${f.file}</div>
            </div>
            <button class="text-xs bg-gray-700 hover:bg-gray-600 px-3 py-1 rounded text-white" 
                onclick="openSourceFile('${f.file}')">View Source</button>
        `;
        container.appendChild(div);
    });
}

function renderDangerous() {
    const container = document.getElementById('dangerousContainer');
    container.innerHTML = '';
    
    findings.filter(f => f.category === 'dangerous').forEach(f => {
        const div = document.createElement('div');
        div.className = 'bg-gray-800 p-3 rounded border border-gray-700 flex justify-between items-center hover:bg-gray-750 transition cursor-pointer';
        div.innerHTML = `
            <div class="flex items-center gap-3">
                <span class="w-2 h-2 rounded-full ${f.severity==='critical'?'bg-red-500':'bg-orange-500'}"></span>
                <div>
                    <div class="text-gray-200 text-sm">${f.message}</div>
                    <div class="text-xs text-gray-500 font-mono">${f.file}:${f.line || '?'}</div>
                </div>
            </div>
            <i class="fa-solid fa-chevron-right text-gray-600"></i>
        `;
        div.onclick = () => openSourceFile(f.file, f.line);
        container.appendChild(div);
    });
}

function renderFileTree() {
    const tree = document.getElementById('fileTree');
    tree.innerHTML = '';
    
    Object.keys(fileMap).sort().forEach(path => {
        const div = document.createElement('div');
        div.className = 'p-1 cursor-pointer hover:bg-gray-700 rounded text-gray-400 truncate';
        div.textContent = path;
        div.onclick = () => openSourceFile(path);
        tree.appendChild(div);
    });
}

async function openSourceFile(path, line = null) {
    switchTab('source');
    const file = fileMap[path];
    if (!file) return;

    const content = await file.async('string');
    const codeBlock = document.getElementById('sourceViewer');
    
    codeBlock.textContent = content;
    // Remove old highlighting class
    codeBlock.className = 'language-javascript h-full text-xs hljs';
    hljs.highlightElement(codeBlock);
    
    // Highlight active line if provided
    // (Note: Simple scroll for now, full line highlighting requires complex DOM manipulation in pre tags)
    if (line) {
        // Simple search for line approximation
        const lines = content.split('\n');
        // This is a basic viewer; for robust line highlighting we usually need CodeMirror. 
        // We will just scroll to top for now or use a simple alert/toast in a real app.
    }
}

// --- UI HELPERS ---

function switchTab(targetId) {
    document.querySelectorAll('.view-section').forEach(el => el.classList.add('hidden'));
    document.getElementById(`view-${targetId}`).classList.remove('hidden');
    
    document.querySelectorAll('.nav-btn').forEach(b => {
        b.classList.remove('active', 'bg-gray-700', 'text-white');
        b.classList.add('text-gray-400');
        if (b.dataset.target === targetId) {
            b.classList.add('active', 'bg-gray-700', 'text-white');
            b.classList.remove('text-gray-400');
        }
    });
}

function toggleLoading(isLoading) {
    const el = document.getElementById('scanStatus');
    if (isLoading) el.classList.remove('hidden');
    else el.classList.add('hidden');
}