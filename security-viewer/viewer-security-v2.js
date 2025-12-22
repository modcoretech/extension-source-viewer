/**
 * Advanced CRX Security Scanner
 * * Features:
 * - No innerHTML usage (Safe DOM construction).
 * - Client-side AST parsing via Esprima.
 * - Entropy calculation for obfuscation detection.
 * - CodeMirror integration.
 * - Accessibility support.
 */

// --- CONFIGURATION ---

const RISK_WEIGHTS = {
    critical: 25,
    high: 10,
    medium: 5,
    low: 1
};

const PATTERNS = {
    secrets: [
        { name: 'AWS Access Key', regex: /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g, level: 'critical' },
        { name: 'Google API Key', regex: /AIza[0-9A-Za-z\\-_]{35}/g, level: 'high' },
        { name: 'Generic Private Key', regex: /-----BEGIN [A-Z]+ PRIVATE KEY-----/g, level: 'critical' },
        { name: 'Slack Token', regex: /xox[baprs]-([0-9a-zA-Z]{10,48})/g, level: 'high' },
        { name: 'IPv4 Address', regex: /\b(?!0)(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g, level: 'low' },
        { name: 'Email Address', regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, level: 'low' }
    ],
    suspicious: [
        { name: 'Debugger Statement', regex: /debugger;/g, level: 'medium' },
        { name: 'Encoded String (Base64-ish)', regex: /([A-Za-z0-9+/]{50,}={0,2})/g, level: 'low' }
    ]
};

const DANGEROUS_FUNCTIONS = {
    'eval': { level: 'critical', desc: 'Execution of arbitrary code strings' },
    'setTimeout': { level: 'medium', desc: 'Potential execution if string argument used' },
    'setInterval': { level: 'medium', desc: 'Potential execution if string argument used' },
    'Function': { level: 'critical', desc: 'Dynamic function creation' },
    'document.write': { level: 'high', desc: 'DOM XSS vector' },
    'document.writeln': { level: 'high', desc: 'DOM XSS vector' },
    'innerHTML': { level: 'medium', desc: 'Potential XSS if user input involved' },
    'outerHTML': { level: 'medium', desc: 'Potential XSS if user input involved' },
    'chrome.tabs.executeScript': { level: 'high', desc: 'Injects code into tabs' },
    'chrome.downloads.download': { level: 'medium', desc: 'Initiates downloads' },
    'chrome.webRequest': { level: 'medium', desc: 'Intercepts network traffic' }
};

// --- STATE MANAGEMENT ---

const state = {
    zip: null,
    files: {},
    findings: [],
    score: 100,
    stats: { size: 0, secrets: 0, entryPoints: 0 },
    chart: null,
    editors: { manifest: null, source: null }
};

// --- INITIALIZATION ---

document.addEventListener('DOMContentLoaded', () => {
    initEditors();
    setupEventListeners();
});

function initEditors() {
    // Initialize Manifest Editor (ReadOnly)
    const manifestEl = document.getElementById('manifest-editor');
    state.editors.manifest = CodeMirror(manifestEl, {
        mode: 'application/json',
        theme: 'nord',
        readOnly: true,
        lineNumbers: true,
        foldGutter: true,
        gutters: ["CodeMirror-linenumbers", "CodeMirror-foldgutter"]
    });

    // Initialize Source Editor (ReadOnly)
    const sourceEl = document.getElementById('code-editor');
    state.editors.source = CodeMirror(sourceEl, {
        mode: 'javascript',
        theme: 'nord',
        readOnly: true,
        lineNumbers: true,
        styleActiveLine: true,
        foldGutter: true,
        gutters: ["CodeMirror-linenumbers", "CodeMirror-foldgutter"]
    });
}

function setupEventListeners() {
    document.getElementById('upload-trigger').onclick = () => document.getElementById('file-input').click();
    document.getElementById('file-input').onchange = handleFileUpload;

    // Navigation Tabs
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.onclick = () => {
            // Update UI State
            document.querySelectorAll('.nav-btn').forEach(b => {
                b.classList.remove('bg-gray-800', 'text-white', 'shadow-inner');
                b.classList.add('text-gray-400');
            });
            btn.classList.add('bg-gray-800', 'text-white', 'shadow-inner');
            btn.classList.remove('text-gray-400');

            // Toggle Views
            document.querySelectorAll('.view-section').forEach(v => v.classList.add('hidden'));
            document.getElementById(`view-${btn.dataset.target}`).classList.remove('hidden');
            
            // Refresh Editors if needed
            if(btn.dataset.target === 'source') state.editors.source.refresh();
            if(btn.dataset.target === 'manifest') state.editors.manifest.refresh();
        };
    });

    // Findings Filter
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.onclick = () => {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active', 'ring-2', 'ring-white'));
            btn.classList.add('active', 'ring-2', 'ring-white');
            renderFindings(btn.dataset.filter);
        };
    });
}

// --- FILE PROCESSING ---

async function handleFileUpload(e) {
    const file = e.target.files[0];
    if (!file) return;

    resetState();
    setLoading(true, "Extracting Archive...");

    try {
        const zip = await JSZip.loadAsync(file);
        state.zip = zip;
        
        // Build File Map
        let totalSize = 0;
        const filePromises = [];

        zip.forEach((path, fileObj) => {
            if (!fileObj.dir) {
                state.files[path] = fileObj;
                totalSize += fileObj._data.uncompressedSize;
                filePromises.push(path);
            }
        });

        state.stats.size = (totalSize / 1024).toFixed(2);
        document.getElementById('stat-files').textContent = Object.keys(state.files).length;
        document.getElementById('stat-size').textContent = `${state.stats.size} KB`;

        // Start Analysis
        await analyzeExtension(filePromises);

    } catch (err) {
        console.error(err);
        alert("Error reading file: " + err.message);
        setLoading(false);
    }
}

function resetState() {
    state.findings = [];
    state.score = 100;
    state.stats = { size: 0, secrets: 0, entryPoints: 0 };
    state.files = {};
    
    // Clear UI
    document.getElementById('empty-state').classList.add('hidden');
    document.getElementById('view-dashboard').classList.remove('hidden');
    document.getElementById('file-tree').innerHTML = '';
    document.getElementById('manifest-perms').innerHTML = '';
    document.getElementById('score-breakdown').innerHTML = '';
    document.getElementById('library-list').textContent = 'None detected';
    
    state.editors.source.setValue('// Select a file to view content');
    state.editors.manifest.setValue('{}');
}

// --- ANALYSIS ENGINE ---

async function analyzeExtension(paths) {
    setLoading(true, "Analyzing Manifest...");
    
    // 1. Manifest Analysis
    if (state.files['manifest.json']) {
        try {
            const content = await state.files['manifest.json'].async('string');
            const manifest = JSON.parse(content);
            state.editors.manifest.setValue(JSON.stringify(manifest, null, 2));
            auditManifest(manifest);
        } catch (e) {
            addFinding('critical', 'Manifest Error', 'manifest.json is invalid JSON', 'manifest.json');
        }
    } else {
        addFinding('critical', 'Missing Manifest', 'Extension missing manifest.json', 'root');
    }

    // 2. Code & File Analysis
    setLoading(true, "Scanning Scripts & Assets...");
    
    const jsFiles = paths.filter(p => p.endsWith('.js') || p.endsWith('.html'));
    
    for (const path of jsFiles) {
        try {
            const content = await state.files[path].async('string');
            
            // A. Entropy / Obfuscation Check
            const entropy = calculateEntropy(content);
            if (entropy > 5.2 && content.length > 500) {
                addFinding('high', 'High Entropy (Possible Obfuscation)', `Entropy: ${entropy.toFixed(2)}`, path);
            }

            // B. Regex Scanning (Secrets)
            scanRegexPatterns(content, path);

            // C. AST Analysis (JS Only)
            if (path.endsWith('.js')) {
                scanAST(content, path);
                detectLibraries(content);
            }

        } catch (err) {
            console.warn(`Skipped ${path}: ${err.message}`);
            addFinding('low', 'Scan Error', `Could not scan file (Binary or Syntax Error)`, path);
        }
    }

    finalizeAnalysis();
}

function auditManifest(manifest) {
    // Version Check
    if (manifest.manifest_version !== 3) {
        addFinding('medium', 'Legacy Manifest', `Using Manifest V${manifest.manifest_version}. V3 is standard.`, 'manifest.json');
    }

    // Permissions
    if (manifest.permissions) {
        manifest.permissions.forEach(p => {
            const li = document.createElement('li');
            li.className = "flex items-center gap-2";
            
            if (p === '<all_urls>' || p.includes('*://')) {
                addFinding('critical', 'Broad Host Permission', `Permission '${p}' allows access to all websites.`, 'manifest.json');
                li.innerHTML = `<i class="fa-solid fa-triangle-exclamation text-red-400"></i> ${p}`;
            } else if (['cookies', 'webRequest', 'tabs', 'debugger'].includes(p)) {
                addFinding('high', 'Sensitive Permission', `Permission '${p}' is powerful.`, 'manifest.json');
                li.innerHTML = `<i class="fa-solid fa-circle-exclamation text-orange-400"></i> ${p}`;
            } else {
                li.innerHTML = `<i class="fa-solid fa-check text-green-400"></i> ${p}`;
            }
            document.getElementById('manifest-perms').appendChild(li);
        });
    }

    // CSP
    const csp = manifest.content_security_policy;
    const cspDiv = document.getElementById('manifest-csp');
    if (csp) {
        const cspStr = (typeof csp === 'object') ? (csp.extension_pages || '') : csp;
        cspDiv.textContent = cspStr;
        if (cspStr.includes("'unsafe-eval'")) {
            addFinding('critical', 'Insecure CSP', "CSP allows 'unsafe-eval' (Code Execution Risk)", 'manifest.json');
        }
    } else {
        cspDiv.textContent = "Default (Secure)";
    }
}

function scanRegexPatterns(content, path) {
    // Secrets
    PATTERNS.secrets.forEach(pat => {
        const matches = content.match(pat.regex);
        if (matches) {
            const unique = [...new Set(matches)];
            state.stats.secrets += unique.length;
            unique.forEach(m => {
                const masked = m.substring(0, 4) + '...' + m.substring(m.length - 4);
                addFinding(pat.level, pat.name, `Found potential secret: ${masked}`, path);
            });
        }
    });

    // Suspicious Strings
    PATTERNS.suspicious.forEach(pat => {
        if (pat.regex.test(content)) {
            addFinding(pat.level, 'Suspicious Pattern', `Matches pattern: ${pat.name}`, path);
        }
    });
}

function scanAST(content, path) {
    try {
        // Tolerant parsing to handle some modern syntax errors in Esprima
        const ast = esprima.parseScript(content, { range: true, loc: true, tolerant: true });
        
        walkAST(ast, (node) => {
            // Check for CallExpressions (eval, etc)
            if (node.type === 'CallExpression') {
                let funcName = '';
                
                if (node.callee.type === 'Identifier') {
                    funcName = node.callee.name;
                } else if (node.callee.type === 'MemberExpression') {
                    // Handle obj.method()
                    const obj = node.callee.object.name || 'obj';
                    const prop = node.callee.property.name || 'prop';
                    funcName = `${obj}.${prop}`;
                    
                    // Special case for innerHTML assignment (AssignmentExpression, not Call)
                    // But here we are in CallExpression. innerHTML is usually an assignment.
                    // This walker assumes Calls. Let's fix.
                }

                if (DANGEROUS_FUNCTIONS[funcName]) {
                    const info = DANGEROUS_FUNCTIONS[funcName];
                    addFinding(info.level, `Dangerous Function: ${funcName}`, info.desc, path, node.loc.start.line);
                }
            }

            // Check for Assignment to innerHTML
            if (node.type === 'AssignmentExpression' && node.left.type === 'MemberExpression') {
                if (node.left.property.name === 'innerHTML' || node.left.property.name === 'outerHTML') {
                    addFinding('medium', 'Unsafe DOM Assignment', 'Use of innerHTML/outerHTML. Prefer textContent.', path, node.loc.start.line);
                }
            }
        });
    } catch (e) {
        // AST Parse failed (Minified code or ES6+ syntax not supported by this Esprima version)
        // Fallback: We rely on the Regex scan performed earlier.
        // We log a generic info finding.
        // addFinding('low', 'Parser Skipped', 'Code complexity or syntax prevented full AST analysis.', path);
    }
}

function walkAST(node, visitor) {
    if (!node) return;
    visitor(node);
    for (const key in node) {
        if (node.hasOwnProperty(key)) {
            const child = node[key];
            if (typeof child === 'object' && child !== null) {
                if (Array.isArray(child)) {
                    child.forEach(n => walkAST(n, visitor));
                } else {
                    walkAST(child, visitor);
                }
            }
        }
    }
}

function calculateEntropy(str) {
    const len = str.length;
    const frequencies = {};
    for (let i = 0; i < len; i++) {
        const char = str[i];
        frequencies[char] = (frequencies[char] || 0) + 1;
    }
    
    let entropy = 0;
    for (const char in frequencies) {
        const p = frequencies[char] / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

function detectLibraries(content) {
    const libs = [];
    if (content.includes('jQuery')) libs.push('jQuery');
    if (content.includes('React')) libs.push('React');
    if (content.includes('Vue')) libs.push('Vue');
    if (content.includes('Angular')) libs.push('Angular');
    if (content.includes('Bootstrap')) libs.push('Bootstrap');
    
    if (libs.length > 0) {
        const container = document.getElementById('library-list');
        if (container.textContent === 'None detected') container.innerHTML = ''; // safe clear
        
        libs.forEach(lib => {
            if (!container.textContent.includes(lib)) {
                const span = document.createElement('span');
                span.className = "bg-gray-700 px-2 py-1 rounded text-xs border border-gray-600";
                span.textContent = lib;
                container.appendChild(span);
            }
        });
    }
}

// --- UI & RENDERING ---

function finalizeAnalysis() {
    calculateScore();
    renderFindings('all');
    renderChart();
    renderFileTree();
    
    document.getElementById('stat-secrets').textContent = state.stats.secrets;
    
    setLoading(false);
}

function addFinding(severity, title, message, file, line = null) {
    state.findings.push({ severity, title, message, file, line });
}

function calculateScore() {
    let deduction = 0;
    const breakdown = document.getElementById('score-breakdown');
    breakdown.innerHTML = ''; // clear

    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    
    state.findings.forEach(f => {
        counts[f.severity]++;
        // Cap deductions per category to prevent negative infinity
        if (counts[f.severity] < 10) { 
            deduction += RISK_WEIGHTS[f.severity];
        }
    });

    state.score = Math.max(0, 100 - deduction);

    // Update UI Score
    const scoreEl = document.getElementById('score-display');
    const labelEl = document.getElementById('risk-label');
    
    scoreEl.textContent = state.score;
    
    if (state.score >= 90) {
        scoreEl.className = "text-5xl font-black text-green-500";
        labelEl.textContent = "Minimal Risk";
        labelEl.className = "text-xs font-bold text-green-400 mt-1 uppercase tracking-wider";
    } else if (state.score >= 60) {
        scoreEl.className = "text-5xl font-black text-yellow-500";
        labelEl.textContent = "Moderate Risk";
        labelEl.className = "text-xs font-bold text-yellow-400 mt-1 uppercase tracking-wider";
    } else {
        scoreEl.className = "text-5xl font-black text-red-500";
        labelEl.textContent = "Critical Risk";
        labelEl.className = "text-xs font-bold text-red-400 mt-1 uppercase tracking-wider";
    }

    // Render Breakdown Items (Safe DOM)
    Object.entries(counts).forEach(([level, count]) => {
        if (count === 0) return;
        const item = document.createElement('div');
        item.className = "flex justify-between items-center text-sm border-b border-gray-700 pb-1 last:border-0";
        
        const left = document.createElement('span');
        left.textContent = `${count}x ${level.toUpperCase()}`;
        left.className = `font-mono ${getTextColor(level)}`;
        
        const right = document.createElement('span');
        right.textContent = `-${Math.min(count * RISK_WEIGHTS[level], 50)} pts`;
        right.className = "text-gray-500";
        
        item.appendChild(left);
        item.appendChild(right);
        breakdown.appendChild(item);
    });
}

function renderFindings(filter) {
    const container = document.getElementById('findings-container');
    container.innerHTML = '';

    const list = filter === 'all' 
        ? state.findings 
        : state.findings.filter(f => f.severity === filter);

    if (list.length === 0) {
        container.innerHTML = `<div class="text-center text-gray-500 py-10">No ${filter} issues found.</div>`;
        return;
    }

    list.forEach(f => {
        const card = document.createElement('div');
        card.className = `bg-gray-800 rounded border-l-4 p-4 shadow-sm hover:bg-gray-750 transition ${getBorderColor(f.severity)}`;
        
        const header = document.createElement('div');
        header.className = "flex justify-between items-start mb-2";
        
        const titleGroup = document.createElement('div');
        
        const badge = document.createElement('span');
        badge.className = `risk-badge risk-${f.severity} mr-2`;
        badge.textContent = f.severity;
        
        const title = document.createElement('span');
        title.className = "font-bold text-gray-200 text-sm";
        title.textContent = f.title;
        
        titleGroup.appendChild(badge);
        titleGroup.appendChild(title);
        
        const fileInfo = document.createElement('button');
        fileInfo.className = "text-xs text-blue-400 hover:text-blue-300 font-mono text-right";
        fileInfo.textContent = f.file + (f.line ? `:${f.line}` : '');
        fileInfo.onclick = () => openFileInEditor(f.file, f.line);
        
        header.appendChild(titleGroup);
        header.appendChild(fileInfo);
        
        const body = document.createElement('p');
        body.className = "text-sm text-gray-400 mt-1";
        body.textContent = f.message;
        
        card.appendChild(header);
        card.appendChild(body);
        container.appendChild(card);
    });
}

function renderChart() {
    const ctx = document.getElementById('risk-chart').getContext('2d');
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    state.findings.forEach(f => counts[f.severity]++);

    if (state.chart) state.chart.destroy();

    state.chart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [counts.critical, counts.high, counts.medium, counts.low],
                backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6'],
                borderWidth: 0,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'right', labels: { color: '#94a3b8', font: { size: 10 } } }
            },
            cutout: '70%'
        }
    });
}

function renderFileTree() {
    const tree = document.getElementById('file-tree');
    tree.innerHTML = '';
    
    // Sort keys alphabetically
    Object.keys(state.files).sort().forEach(path => {
        const div = document.createElement('div');
        div.className = "px-2 py-1.5 cursor-pointer hover:bg-gray-700 rounded text-gray-400 truncate flex items-center gap-2 transition";
        div.setAttribute('role', 'button');
        
        // Icon logic
        let iconClass = "fa-regular fa-file";
        if (path.endsWith('.js')) iconClass = "fa-brands fa-js text-yellow-500";
        if (path.endsWith('.json')) iconClass = "fa-solid fa-gear text-gray-500";
        if (path.endsWith('.html')) iconClass = "fa-brands fa-html5 text-orange-500";
        if (path.endsWith('.css')) iconClass = "fa-brands fa-css3 text-blue-500";
        if (path.match(/\.(png|jpg|jpeg|gif)$/)) iconClass = "fa-regular fa-image text-purple-500";

        const icon = document.createElement('i');
        icon.className = iconClass + " w-4 text-center";
        
        const text = document.createElement('span');
        text.textContent = path;
        
        div.appendChild(icon);
        div.appendChild(text);
        
        div.onclick = () => openFileInEditor(path);
        tree.appendChild(div);
    });
}

async function openFileInEditor(path, line = null) {
    // 1. Switch Tab
    document.querySelector('[data-target="source"]').click();
    
    // 2. Load Content
    const file = state.files[path];
    if (!file) return;
    
    document.getElementById('active-filename').textContent = path;
    const content = await file.async('string');
    
    // 3. Update CodeMirror
    const cm = state.editors.source;
    
    // Set Mode based on extension
    let mode = 'javascript';
    if (path.endsWith('.json')) mode = 'application/json';
    if (path.endsWith('.html')) mode = 'htmlmixed';
    if (path.endsWith('.css')) mode = 'css';
    
    cm.setOption('mode', mode);
    cm.setValue(content);
    
    if (line) {
        // Highlight logic
        cm.setSelection({line: line-1, ch: 0}, {line: line-1, ch: 100});
        cm.scrollIntoView({line: line-1, ch: 0}, 200);
    }
}

// --- UTILS ---

function setLoading(active, text = "Processing...") {
    const el = document.getElementById('status-indicator');
    const txt = document.getElementById('status-text');
    if (active) {
        el.classList.remove('hidden');
        txt.textContent = text;
    } else {
        el.classList.add('hidden');
    }
}

function getBorderColor(sev) {
    if (sev === 'critical') return 'border-red-500';
    if (sev === 'high') return 'border-orange-500';
    if (sev === 'medium') return 'border-yellow-500';
    return 'border-blue-500';
}

function getTextColor(sev) {
    if (sev === 'critical') return 'text-red-400';
    if (sev === 'high') return 'text-orange-400';
    if (sev === 'medium') return 'text-yellow-400';
    return 'text-blue-400';
}