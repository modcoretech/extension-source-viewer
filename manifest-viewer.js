// --- CONFIGURATION ---
const MANIFEST_FILE = 'manifest.json';

// --- NEW CONFIG: PERMISSION WEIGHTS AND GROUPS ---
const PERMISSION_WEIGHTS = {
    // High Risk: Full access to user data/network/system
    HIGH: { weight: 3, permissions: ['<all_urls>', '*://*/*', 'webRequest', 'webRequestBlocking', 'debugger', 'nativeMessaging', 'proxy', 'tabs', 'history'] },
    // Medium Risk: Sensitive data access or UI manipulation
    MEDIUM: { weight: 2, permissions: ['scripting', 'cookies', 'downloads', 'topSites', 'clipboardRead', 'alarms', 'management', 'bookmarks', 'geolocation'] },
    // Low Risk: Limited data/storage access
    LOW: { weight: 1, permissions: ['storage', 'unlimitedStorage', 'identity', 'contextMenus', 'notifications', 'offscreen', 'action'] }
};

// --- NEW CONFIG: ACCESSIBILITY CHECKS ---
const ACCESSIBILITY_WEIGHTS = {
    'action.default_title': { weight: 3, check: (m) => getNestedProperty('action.default_title', m) || getNestedProperty('browser_action.default_title', m) || getNestedProperty('page_action.default_title', m) },
    'description': { weight: 4, check: (m) => m.description && m.description.length >= 10 },
    'icon_png': { weight: 2, check: (m) => m.icons && Object.values(m.icons).some(path => path.toLowerCase().endsWith('.png') || path.toLowerCase().endsWith('.svg')) },
    'options_ui': { weight: 1, check: (m) => m.options_ui || m.options_page },
};

// Define detailed properties, their icons, security/info notes, and DEPENDENCIES (new)
const MANIFEST_PROPS = {
    // Basic Info
    'manifest_version': { title: 'Manifest Version', icon: 'fa-solid fa-code-branch', security: true, badge: (v) => v === 3 ? 'badge-mv3' : 'badge-mv2', info: 'MV3 (Version 3) is the modern, secure standard and mandates service workers for background logic. MV2 is deprecated and uses persistent background scripts.' },
    'name': { title: 'Name', icon: 'fa-solid fa-id-card-clip' },
    'version': { title: 'Version', icon: 'fa-solid fa-tag' },
    'description': { title: 'Description', icon: 'fa-solid fa-info-circle' },
    'homepage_url': { title: 'Homepage URL', icon: 'fa-solid fa-house-chimney' },
    'author': { title: 'Author/Developer', icon: 'fa-solid fa-user-tie' },
    
    // Core Functionality & Entry Points (with Dependencies)
    'action': { title: 'Action (Toolbar Popup)', icon: 'fa-solid fa-square-arrow-up-right', security: false, children: ['action.default_popup', 'action.default_title', 'action.default_icon'], info: 'The main toolbar popup/UI for the extension (MV3). Contains `default_popup` or `default_title`. This is the user\'s primary interaction point.' },
    'browser_action': { title: 'Browser Action (MV2 Deprecated)', icon: 'fa-solid fa-square-arrow-up-right', security: true, children: ['browser_action.default_popup', 'browser_action.default_title', 'browser_action.default_icon'], info: 'Deprecated main toolbar popup/UI (MV2). Old extensions use this. Check this property for legacy APIs.' },
    'page_action': { title: 'Page Action (MV2 Deprecated)', icon: 'fa-solid fa-file-export', security: true, children: ['page_action.default_popup', 'page_action.default_title', 'page_action.default_icon'], info: 'Deprecated URL-specific popup (MV2). Only appears on matching URLs. Check this property for legacy APIs.' },
    'background': { title: 'Background Script/Worker', icon: 'fa-solid fa-microchip', security: true, children: ['background.service_worker', 'background.scripts', 'background.persistent'], info: 'Persistent scripts (MV2) or **Service Workers (MV3)** that run the extension\'s main, always-on logic. This is the core engine.' },
    'content_scripts': { title: 'Content Scripts (Code Injection)', icon: 'fa-solid fa-user-secret', security: true, info: 'These scripts are injected into web pages and run in the context of the page, allowing them to read/modify page content. **Critical for security analysis:** check the `matches` patterns.' },
    'options_page': { title: 'Options Page URL (MV2/3)', icon: 'fa-solid fa-sliders', info: 'A separate HTML file for configuring extension settings. Often the source of complex logic or external dependencies.' },
    'options_ui': { title: 'Options UI (MV3 Recommended)', icon: 'fa-solid fa-sliders', children: ['options_ui.page', 'options_ui.open_in_tab'], info: 'The modern way to define the options interface (MV3).' },
    
    // Security, Isolation, & Permissions
    'permissions': { title: 'Required Permissions (APIs)', icon: 'fa-solid fa-key', security: true, info: 'Permissions grant access to sensitive browser APIs (e.g., `tabs`, `storage`, `unlimitedStorage`, `webRequest`). Less sensitive permissions like `storage` are common, but high-impact ones like `tabs` and `webRequest` are serious.' },
    'host_permissions': { title: 'Host Permissions (URL Access)', icon: 'fa-solid fa-user-lock', security: true, info: 'Grants access to specific URL patterns, allowing full control (reading/modifying) over those websites. **CRITICAL RISK:** Look for `<all_urls>` which grants total access to all websites.' },
    'incognito': { title: 'Incognito Mode Behavior', icon: 'fa-solid fa-mask', info: 'Defines if the extension runs in incognito windows (`spanning` (default), `split`, or `not_allowed`). `split` is often required for special use cases.' },
    'content_security_policy': { title: 'Content Security Policy (CSP)', icon: 'fa-solid fa-shield-halved', security: true, info: 'A custom CSP can override default browser security for extension pages. **HIGH RISK:** Check for overly permissive settings like `unsafe-eval` or `unsafe-inline` as they enable XSS vulnerabilities.' },
    'externally_connectable': { title: 'Externally Connectable', icon: 'fa-solid fa-right-left', security: true, children: ['externally_connectable.matches'], info: 'Allows external webpages or other extensions to connect and send messages. **High-risk** if `matches` is misconfigured to allow communication with wide origins.' },
    'web_accessible_resources': { title: 'Web Accessible Resources', icon: 'fa-solid fa-globe', security: true, info: 'Files (scripts, images) that can be loaded by *any* external website. Can be misused for fingerprinting, bypassing CSPs, or for cross-site communication risks.' },
    'declarative_net_request': { title: 'Net Request Rules', icon: 'fa-solid fa-filter', security: false, children: ['declarative_net_request.rule_resources'], info: 'Used for blocking/modifying network requests (e.g., ad blocking). Requires high permissions but is the modern, performant standard for network control (MV3).' },
    
    // UI Elements
    'commands': { title: 'Keyboard Commands', icon: 'fa-solid fa-keyboard' },
    'icons': { title: 'Icons/Assets', icon: 'fa-solid fa-icons' },

    // Nested properties (used for the Dependency Tree visualization)
    'action.default_popup': { title: 'Default Popup HTML', icon: 'fa-solid fa-window-maximize' },
    'action.default_title': { title: 'Default Tooltip', icon: 'fa-solid fa-comment' },
    'action.default_icon': { title: 'Default Icon Path', icon: 'fa-solid fa-image' },
    'browser_action.default_popup': { title: 'Default Popup HTML (MV2)', icon: 'fa-solid fa-window-maximize' },
    'browser_action.default_title': { title: 'Default Tooltip (MV2)', icon: 'fa-solid fa-comment' },
    'browser_action.default_icon': { title: 'Default Icon Path (MV2)', icon: 'fa-solid fa-image' },
    'page_action.default_popup': { title: 'Default Popup HTML (MV2)', icon: 'fa-solid fa-window-maximize' },
    'page_action.default_title': { title: 'Default Tooltip (MV2)', icon: 'fa-solid fa-comment' },
    'page_action.default_icon': { title: 'Default Icon Path (MV2)', icon: 'fa-solid fa-image' },
    'background.service_worker': { title: 'Service Worker File', icon: 'fa-solid fa-cogs' },
    'background.scripts': { title: 'Background Scripts (MV2)', icon: 'fa-solid fa-file-code' },
    'background.persistent': { title: 'Persistent (MV2)', icon: 'fa-solid fa-hourglass-half' },
    'options_ui.page': { title: 'Options Page Path (MV3)', icon: 'fa-solid fa-file-lines' },
    'options_ui.open_in_tab': { title: 'Opens in new tab?', icon: 'fa-solid fa-arrow-up-right-from-square' },
    'externally_connectable.matches': { title: 'Allowed Host Patterns', icon: 'fa-solid fa-sitemap' },
    'declarative_net_request.rule_resources': { title: 'Rule Resource Files', icon: 'fa-solid fa-list-check' },
};

// Define the order and grouping of properties for the analysis panel
const SECTIONS = [
    { name: 'Core Details & Identity', props: ['name', 'version', 'manifest_version', 'description', 'author', 'homepage_url'] },
    { name: 'Security & Host Access', props: ['permissions', 'host_permissions', 'externally_connectable', 'web_accessible_resources', 'content_security_policy', 'incognito'] },
    { name: 'Entry Points & Runtime Logic', props: ['action', 'browser_action', 'page_action', 'background', 'content_scripts', 'options_page', 'options_ui', 'declarative_net_request', 'commands'] },
    { name: 'Assets & UI Elements', props: ['icons'] },
];

// Critical Permissions for Security Flagging (Now derived from PERMISSION_WEIGHTS)
const CRITICAL_PERMISSIONS = Object.values(PERMISSION_WEIGHTS).flatMap(g => g.permissions);

// --- STATE ---
let codeMirrorEditor;
let currentManifest = null;
let elements = {};
let riskScore = 0;
let accessibilityScore = 0;

// --- INITIALIZATION & UTILITIES ---

function cacheElements() {
    // Cache all necessary DOM elements for robust access
    const ids = [
        'crxInput', 'dropOverlay', 'loadingOverlay', 'welcomeState', 'detailsContent',
        'jsonEditorWrapper', 'extName', 'extVersion', 'extBadges', 'manifestSections',
        'copyJsonBtn', 'toast', 'toastMsg', 'toastIcon', 'extDescription',
        'detailsPanel', 'jsonEditorPanel', 'splitContainer', 'jsonLineCol',
        'detailModal', 'modalContent', 'modalTitle', 'modalIcon', 'modalDescription', 
        'modalRawJson', 'modalArrayContent', 'modalArrayCount', 'modalArray',
        'propertyFilter' // <-- NEW: Search input
    ];
    
    ids.forEach(id => {
        elements[id] = document.getElementById(id);
    });
}

function initCodeMirror() {
    if(!elements.jsonEditorWrapper) return;
    
    codeMirrorEditor = CodeMirror(elements.jsonEditorWrapper, {
        mode: 'application/json',
        theme: 'dracula',
        lineNumbers: true,
        autoCloseBrackets: true,
        matchBrackets: true,
        foldGutter: true,
        gutters: ["CodeMirror-linenumbers", "CodeMirror-foldgutter"],
        readOnly: true, // JSON Manifest is Read-Only
        lineWrapping: true,
    });
    
    codeMirrorEditor.on("cursorActivity", () => {
        const cursor = codeMirrorEditor.getCursor();
        if(elements.jsonLineCol) elements.jsonLineCol.textContent = `Ln ${cursor.line + 1}, Col ${cursor.ch + 1}`;
    });
    
    codeMirrorEditor.setValue('// Drop or select an extension file (CRX/ZIP/XPI) to load and analyze its manifest.json.\n// The raw JSON content will appear here.\n');
}

function initEventListeners() {
    elements.crxInput.onchange = (e) => loadFile(e.target.files[0]);
    
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        document.body.addEventListener(eventName, preventDefaults, false);
    });

    document.body.addEventListener('dragenter', () => elements.dropOverlay.classList.remove('hidden'));
    
    elements.dropOverlay.addEventListener('dragleave', (e) => {
        if (e.target === elements.dropOverlay) elements.dropOverlay.classList.add('hidden');
    });
    
    elements.dropOverlay.addEventListener('drop', (e) => {
        elements.dropOverlay.classList.add('hidden');
        if (e.dataTransfer.files[0]) loadFile(e.dataTransfer.files[0]);
    });

    elements.copyJsonBtn.onclick = copyJson;
    
    elements.detailModal.addEventListener('click', (e) => {
        if (e.target === elements.detailModal) {
            closeDetailModal();
        }
    });

    // NEW: Main Filter Listener
    if (elements.propertyFilter) {
        elements.propertyFilter.addEventListener('input', (e) => {
            filterManifestDetails(e.target.value);
        });
    }
}

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

function initApp() {
    cacheElements();
    initCodeMirror();
    initEventListeners();
    closeDetailModal();
}
window.initApp = initApp;


/**
 * Extracts a nested property from the manifest using a dot-separated key (e.g., 'action.default_popup').
 * @param {string} key 
 * @param {object} manifest 
 * @returns {*} The value, or undefined.
 */
function getNestedProperty(key, manifest) {
    const parts = key.split('.');
    let current = manifest;
    for (const part of parts) {
        if (current && typeof current === 'object' && current.hasOwnProperty(part)) {
            current = current[part];
        } else {
            return undefined;
        }
    }
    return current;
}

// --- SCORING LOGIC ---

/**
 * Calculates a Risk Score (0-10) for the extension based on permissions and dangerous flags.
 */
function calculateRiskScore(manifest) {
    let score = 0;

    const allPermissions = [
        ...(manifest.permissions || []),
        ...(manifest.host_permissions || [])
    ];
    
    // 1. Permission Weights
    allPermissions.forEach(perm => {
        let weight = 0;
        for (const group of Object.values(PERMISSION_WEIGHTS)) {
            if (group.permissions.includes(perm) || perm === '<all_urls>' || perm.includes('://*/*')) {
                weight = group.weight;
                break;
            }
        }
        score += weight;
    });

    // 2. High-Risk Property Bonuses 
    if (allPermissions.includes('<all_urls>') || allPermissions.includes('*://*/*')) {
        score += 5; 
    }
    
    if (manifest.content_scripts) {
        manifest.content_scripts.forEach(script => {
            if ((script.matches || []).includes('<all_urls>') || (script.matches || []).some(m => m.includes('://*/*'))) {
                score += 3;
            }
        });
    }

    const csp = manifest.content_security_policy || '';
    if (csp.includes('unsafe-eval') || csp.includes('unsafe-inline')) {
        score += 2;
    }
    
    if (manifest.web_accessible_resources && manifest.web_accessible_resources.length > 0) {
        if (manifest.web_accessible_resources.some(r => r.matches && r.matches.includes('<all_urls>'))) {
            score += 2;
        } else {
            score += 1;
        }
    }

    // Normalize to 10
    return Math.min(10, Math.round(score));
}

/**
 * Calculates an Accessibility Score (0-10) based on recommended manifest features.
 */
function calculateAccessibilityScore(manifest) {
    let score = 0;
    let maxPossibleScore = Object.values(ACCESSIBILITY_WEIGHTS).reduce((sum, item) => sum + item.weight, 0);

    for (const key in ACCESSIBILITY_WEIGHTS) {
        const item = ACCESSIBILITY_WEIGHTS[key];
        if (item.check(manifest)) {
            score += item.weight;
        }
    }
    
    if (maxPossibleScore === 0) return 10; 
    return Math.min(10, Math.round((score / maxPossibleScore) * 10));
}

// --- MAIN LOGIC ---

async function loadFile(file) {
    if (!file) return;

    elements.loadingOverlay.classList.remove('hidden');
    elements.copyJsonBtn.classList.add('hidden');
    
    elements.welcomeState.classList.remove('hidden');
    elements.detailsContent.classList.add('hidden');
    elements.manifestSections.innerHTML = '';
    closeDetailModal();

    elements.extName.textContent = 'Extension Name';
    elements.extVersion.textContent = 'Version: N/A';
    elements.extDescription.textContent = '';
    elements.extBadges.innerHTML = '';
    elements.propertyFilter.value = '';
    codeMirrorEditor.setValue('// Loading...');

    setTimeout(async () => {
        try {
            const arrayBuffer = await file.arrayBuffer();
            const zip = await JSZip.loadAsync(arrayBuffer);
            
            const manifestFile = zip.file(MANIFEST_FILE);
            if (!manifestFile) {
                throw new Error(`The file does not contain a '${MANIFEST_FILE}'.`);
            }
            
            const manifestString = await manifestFile.async('string');
            const manifestJson = JSON.parse(manifestString);
            currentManifest = manifestJson;

            displayManifestDetails(manifestJson);
            displayRawJson(manifestString);
            
            elements.welcomeState.classList.add('hidden');
            elements.detailsContent.classList.remove('hidden');
            elements.copyJsonBtn.classList.remove('hidden');
            showToast('Analysis Complete', 'border-green-500', `${file.name} loaded.`);
            
        } catch (e) {
            console.error("Load Error:", e);
            elements.welcomeState.classList.remove('hidden');
            elements.detailsContent.classList.add('hidden');
            displayRawJson(`// Error loading manifest:\n// ${e.message}\n\n// Ensure the file is a valid CRX/ZIP and contains a 'manifest.json' file.`);
            showToast(`Error: ${e.message.split(':').pop().trim()}`, 'border-red-500', null);
        } finally {
            elements.loadingOverlay.classList.add('hidden');
        }
    }, 100);
}

// --- DISPLAY FUNCTIONS ---

function displayManifestDetails(manifest) {
    currentManifest = manifest;
    riskScore = calculateRiskScore(manifest);
    accessibilityScore = calculateAccessibilityScore(manifest);
    
    elements.extName.textContent = manifest.name || 'Unknown Extension';
    elements.extVersion.textContent = `Version: ${manifest.version || 'N/A'}`;
    elements.extDescription.textContent = manifest.description || 'No description provided.';
    
    // --- Badges & Scores ---
    elements.extBadges.innerHTML = '';
    const version = manifest.manifest_version;
    const isMV3 = version === 3;
    
    // 1. MV Version Badge
    let mvBadgeClass = isMV3 ? 'badge-mv3' : (version === 2 ? 'badge-mv2' : 'bg-gray-700 text-gray-300');
    elements.extBadges.appendChild(createBadge(`MV${version || 'N/A'}`, mvBadgeClass, 'fa-solid fa-code-branch'));
    
    // 2. Risk Score Badge
    const riskColor = riskScore >= 7 ? 'badge-security' : (riskScore >= 4 ? 'badge-warning' : 'bg-green-700 text-white');
    elements.extBadges.appendChild(createBadge(`RISK: ${riskScore}/10`, riskColor, 'fa-solid fa-user-shield'));

    // 3. Accessibility Score Badge
    const accessColor = accessibilityScore >= 8 ? 'bg-blue-600 text-white' : (accessibilityScore >= 5 ? 'bg-yellow-600 text-white' : 'badge-security');
    elements.extBadges.appendChild(createBadge(`A11Y: ${accessibilityScore}/10`, accessColor, 'fa-solid fa-universal-access'));

    // 4. Other Security Badges
    const permissions = manifest.permissions || [];
    const hostPermissions = manifest.host_permissions || [];
    const allAccess = permissions.includes('<all_urls>') || hostPermissions.includes('<all_urls>') || hostPermissions.includes('*://*/*');

    if (allAccess) {
        elements.extBadges.appendChild(createBadge('CRITICAL: All Hosts Access', 'badge-security', 'fa-solid fa-skull-crossbones'));
    } 
    
    if (manifest.content_scripts && manifest.content_scripts.length > 0) {
         elements.extBadges.appendChild(createBadge('Logic: Code Injection', 'bg-purple-900/50 text-purple-300 border border-purple-700/50', 'fa-solid fa-code'));
    }
    
    const csp = manifest.content_security_policy || '';
    if (csp.includes('unsafe-eval') || csp.includes('unsafe-inline')) {
         elements.extBadges.appendChild(createBadge('CSP Risk: Unsafe Code', 'badge-security', 'fa-solid fa-virus'));
    }


    // --- Sections ---
    renderPropertySections(manifest, elements.propertyFilter.value);
}

function renderPropertySections(manifest, filterText = '') {
    elements.manifestSections.innerHTML = '';
    const filterLower = filterText.toLowerCase().trim();

    SECTIONS.forEach(section => {
        const sectionContainer = document.createElement('div');
        sectionContainer.className = 'section-container';

        const header = document.createElement('h3');
        header.className = 'manifest-section-header';
        header.textContent = section.name;
        sectionContainer.appendChild(header);

        let sectionHasVisibleContent = false;
        
        section.props.forEach(propKey => {
            const item = createDetailItemRecursive(propKey, manifest);
            
            if (item) {
                // Check if the item's title/value, or any of its children, match the filter
                const matchesFilter = (item.textContent.toLowerCase().includes(filterLower) || filterLower === '');
                
                if (matchesFilter) {
                    sectionHasVisibleContent = true;
                    sectionContainer.appendChild(item);
                }
            }
        });
        
        // Add a placeholder if section is empty after filtering
        if (!sectionHasVisibleContent && filterLower === '') {
            const p = document.createElement('p');
            p.className = 'text-xs text-gray-600 italic py-2';
            p.textContent = `No ${section.name.toLowerCase()} properties found or relevant for analysis.`;
            sectionContainer.appendChild(p);
        }

        if (sectionHasVisibleContent || filterLower === '') {
             elements.manifestSections.appendChild(sectionContainer);
        }
    });
}


/**
 * Renders a property and its children recursively (for Dependency Tree visualization).
 * @param {string} propKey The manifest key (e.g., 'action' or 'action.default_popup').
 * @param {object} manifest The full manifest object.
 * @returns {HTMLElement|null} The created item element, or null if value is empty/undefined.
 */
function createDetailItemRecursive(propKey, manifest) {
    const value = getNestedProperty(propKey, manifest);
    
    // Skip empty/default values
    if (value === null || value === undefined) return null;
    if (Array.isArray(value) && value.length === 0) return null;
    if (typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 0) return null;
    if (typeof value === 'string' && value.trim() === '') return null;

    const def = MANIFEST_PROPS[propKey] || { title: propKey, icon: 'fa-regular fa-file-alt', security: false, info: 'No specific information available.' };
    
    // Main Container
    const itemContainer = document.createElement('div');
    itemContainer.className = 'manifest-property-container';
    
    // Main Item Header (the clickable/collapsible part)
    const item = document.createElement('div');
    item.className = 'manifest-item group relative';
    item.dataset.key = propKey;

    // Left: Icon + Title + Info Tooltip + Collapse Icon
    const left = document.createElement('div');
    left.className = 'flex items-center gap-3 w-1/2';
    
    const isParent = def.children && def.children.length > 0 && def.children.some(childKey => getNestedProperty(childKey, manifest) !== undefined);
    
    if (isParent) {
        const collapseIcon = document.createElement('i');
        collapseIcon.className = 'fa-solid fa-angle-right text-gray-500 transition-transform duration-200 cursor-pointer';
        left.appendChild(collapseIcon);
        // Add click listener on the whole row for collapsing later
    } else {
        left.innerHTML += '<i class="fa-solid fa-angle-right text-transparent mr-1"></i>'; 
    }
    
    // Icon and Title
    const icon = document.createElement('i');
    const iconColor = def.security ? 'text-red-400' : 'text-blue-400';
    icon.className = `${def.icon} w-4 text-center ${iconColor}`;
    left.appendChild(icon);

    const title = document.createElement('span');
    title.className = 'manifest-item-title';
    title.textContent = def.title;
    left.appendChild(title);
    
    // Tooltip for Info
    const infoIcon = document.createElement('i');
    infoIcon.className = 'fa-solid fa-circle-info text-gray-600 hover:text-gray-400 cursor-help transition ml-1 text-sm';
    infoIcon.title = def.info;
    left.appendChild(infoIcon);
    
    item.appendChild(left);

    // Right: Value Display (rest remains same)
    let valueDisplay = '';
    let isClickable = false;

    if (Array.isArray(value)) {
        valueDisplay = `${value.length} item${value.length === 1 ? '' : 's'}`;
        if (propKey === 'permissions' || propKey === 'host_permissions') {
             const criticalCount = value.filter(p => CRITICAL_PERMISSIONS.includes(p) || p.includes('://*/*')).length;
             valueDisplay += ` (${criticalCount > 0 ? `${criticalCount} critical` : 'no critical'})`;
        }
        isClickable = value.length > 0;
        
    } else if (typeof value === 'object' && value !== null) {
        const keys = Object.keys(value);
        valueDisplay = `(Object: ${keys.length} key${keys.length === 1 ? '' : 's'})`;
        isClickable = keys.length > 0 && !isParent; 
        
    } else if (typeof value === 'string') {
        valueDisplay = value.length > 40 ? value.substring(0, 37) + '...' : value;
        if (value.length > 40) isClickable = true;
    } else if (typeof value === 'boolean') {
        valueDisplay = value ? 'True' : 'False';
    } else {
        valueDisplay = String(value);
    }
    
    const valueSpan = document.createElement('span');
    valueSpan.className = `manifest-item-value ${isClickable ? 'cursor-pointer hover:text-white underline decoration-dashed decoration-gray-600' : ''}`;
    valueSpan.textContent = valueDisplay;
    item.appendChild(valueSpan);
    
    // Add click handler for modal
    if (isClickable) {
        item.onclick = (e) => {
             // Stop propagation to prevent dependency tree collapse on modal open
             e.stopPropagation(); 
             openDetailModal(propKey, value);
        };
    }
    
    itemContainer.appendChild(item);

    // Children/Dependency Panel (Hidden by default)
    if (isParent) {
        const childrenPanel = document.createElement('div');
        childrenPanel.className = 'manifest-children-panel hidden';
        
        let childrenCount = 0;
        def.children.forEach(childKey => {
            const childItem = createDetailItemRecursive(childKey, manifest);
            if (childItem) {
                childrenCount++;
                childrenPanel.appendChild(childItem);
            }
        });
        
        if (childrenCount > 0) {
            itemContainer.appendChild(childrenPanel);
            
            // Allow the main item to toggle the children panel
            const collapseIcon = left.querySelector('.fa-angle-right');
            item.onclick = (e) => {
                // Default click action is now for collapse/expand unless overridden by isClickable above
                if (!isClickable) {
                    childrenPanel.classList.toggle('hidden');
                    collapseIcon.classList.toggle('rotate-90');
                } else {
                    // For clickable parents (e.g., array/object), use the default click handler
                    item.querySelector('.manifest-item-value').click();
                }
            };
        }
    }

    return itemContainer;
}

function filterManifestDetails(filterText) {
    if (!currentManifest) return;
    renderPropertySections(currentManifest, filterText);
    
    // Also update the filter in the modal if it's open
    const modal = elements.detailModal;
    if(!modal.classList.contains('hidden')) {
        const modalPropKey = elements.modalTitle.dataset.propkey;
        const modalValue = JSON.parse(modal.dataset.value);
        // Use the modal's internal filter value if present, otherwise use the main filter text as default
        const modalFilterInput = modal.querySelector('#modalArrayFilter');
        const activeFilter = modalFilterInput ? modalFilterInput.value : filterText; 
        openDetailModal(modalPropKey, modalValue, activeFilter);
    }
}

// --- MODAL FUNCTIONS ---

function openDetailModal(propKey, value, filterText = '') {
    const def = MANIFEST_PROPS[propKey] || { title: propKey, icon: 'fa-regular fa-file-alt', security: false, info: 'No specific information available for this property.' };
    
    elements.modalTitle.dataset.propkey = propKey;
    elements.detailModal.dataset.value = JSON.stringify(value); 
    
    elements.modalTitle.textContent = def.title;
    elements.modalDescription.textContent = def.info;
    
    const iconColor = def.security ? 'text-red-400' : 'text-blue-400';
    elements.modalIcon.className = `${def.icon} ${iconColor}`;
    
    let jsonText;
    try {
        jsonText = JSON.stringify(value, null, 2);
    } catch (e) {
        jsonText = String(value);
    }
    elements.modalRawJson.textContent = jsonText;
    
    // 3. Set Array/List Content
    elements.modalArray.innerHTML = '';
    
    if (Array.isArray(value) && value.length > 0) {
        elements.modalArrayContent.classList.remove('hidden');
        
        // Add array filter input 
        let filterWrapper = elements.modalArrayContent.querySelector('#modalFilterWrapper');
        if (!filterWrapper) {
            filterWrapper = document.createElement('div');
            filterWrapper.id = 'modalFilterWrapper';
            filterWrapper.innerHTML = `
                <input type="text" id="modalArrayFilter" placeholder="Filter array items..." 
                    class="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-sm text-white focus:ring-blue-500 focus:border-blue-500 mb-3">
            `;
            elements.modalArrayContent.insertBefore(filterWrapper, elements.modalArrayContent.firstChild);

            // Add the event listener to the *newly created* filter input
            const filterInput = elements.modalArrayContent.querySelector('#modalArrayFilter');
            filterInput.addEventListener('input', (e) => openDetailModal(propKey, value, e.target.value));
        }
        
        const filterInput = elements.modalArrayContent.querySelector('#modalArrayFilter');
        filterInput.value = filterText; 

        let visibleCount = 0;
        const filterLower = filterText.toLowerCase().trim();
        
        value.forEach((item, index) => {
            const rawValue = typeof item === 'object' ? JSON.stringify(item) : String(item);
            const rawValueLower = rawValue.toLowerCase();

            if (filterLower !== '' && !rawValueLower.includes(filterLower)) {
                return; 
            }
            
            visibleCount++;
            
            const li = document.createElement('li');
            li.className = 'p-3 text-sm flex flex-col justify-between items-start';
            
            let statusBadge = '';
            let contentVisualization = '';
            
            // Permission/Host Permission Logic
            if (propKey === 'permissions' || propKey === 'host_permissions') {
                let currentBadgeClass = 'bg-gray-700 text-gray-200';
                let currentBadgeText = 'LOW RISK';
                let currentIcon = 'fa-solid fa-lock';
                
                for (const groupKey in PERMISSION_WEIGHTS) {
                    const group = PERMISSION_WEIGHTS[groupKey];
                    if (group.permissions.includes(rawValue) || rawValue.includes('<all_urls>') || rawValue.includes('://*/*')) {
                        currentBadgeText = `${groupKey} RISK`;
                        if (groupKey === 'HIGH') {
                            currentBadgeClass = 'badge-security';
                            currentIcon = 'fa-solid fa-triangle-exclamation';
                        } else if (groupKey === 'MEDIUM') {
                            currentBadgeClass = 'badge-warning';
                            currentIcon = 'fa-solid fa-shield-virus';
                        }
                        break;
                    }
                }
                statusBadge = createBadge(currentBadgeText, currentBadgeClass, currentIcon).outerHTML;
            } 
            
            // Content Script Visualization Logic (New)
            else if (propKey === 'content_scripts') {
                const matches = item.matches || [];
                const runAt = item.run_at || 'document_idle';
                const mainFile = (item.js && item.js[0]) || (item.css && item.css[0]) || 'No files specified';
                
                statusBadge = createBadge(`Run At: ${runAt}`, 'bg-purple-700/50 text-purple-200', 'fa-solid fa-clock').outerHTML;
                
                contentVisualization = `
                    <div class="mt-2 w-full">
                        <span class="font-semibold text-gray-300 block mb-2">File: <span class="text-blue-300 font-mono">${mainFile}</span></span>
                        <span class="font-semibold text-gray-300 block mb-1">Match Patterns (${matches.length}):</span>
                        <ul class="ml-0 space-y-2">
                            ${matches.map(pattern => {
                                const { highlightedHTML, group, example } = highlightUrlPattern(pattern);
                                return `
                                    <li class="bg-gray-900/50 p-3 rounded-lg border border-gray-700/50">
                                        <div class="font-mono text-gray-200 text-xs break-all">${highlightedHTML}</div>
                                        <div class="flex items-center text-gray-500 mt-1 text-xs">
                                            <i class="${MANIFEST_PROPS.host_permissions.icon} mr-1 text-sm"></i>
                                            <span class="mr-3 font-semibold text-gray-400">${group}</span>
                                            <span class="italic">Example: ${example}</span>
                                        </div>
                                    </li>
                                `;
                            }).join('')}
                        </ul>
                    </div>
                `;
            }
            
            // Default list item rendering
            if (propKey !== 'content_scripts') {
                li.innerHTML = `
                    <div class="w-full flex justify-between items-start">
                        <span class="font-mono text-gray-100 break-all">${rawValue.substring(0, 100)}${rawValue.length > 100 ? '...' : ''}</span>
                        <div>${statusBadge}</div>
                    </div>
                    <span class="text-xs text-gray-500 mt-1">Index: ${index}</span>
                `;
            } else {
                 li.innerHTML = `
                    <div class="w-full flex justify-between items-start mb-2">
                        <span class="font-bold text-lg text-white">Content Script #${index + 1}</span>
                        <div>${statusBadge}</div>
                    </div>
                    ${contentVisualization}
                `;
            }
            elements.modalArray.appendChild(li);
        });

        elements.modalArrayCount.textContent = visibleCount;
        
        if (visibleCount === 0 && filterText !== '') {
            elements.modalArray.innerHTML = `<li class="p-4 text-center text-gray-500 italic">No items matched your filter "${filterText}".</li>`;
        }

        
    } else {
        elements.modalArrayContent.classList.add('hidden');
    }
    
    if (elements.detailModal.classList.contains('hidden')) {
        elements.detailModal.classList.remove('hidden');
        setTimeout(() => {
            elements.modalContent.classList.remove('scale-95', 'opacity-0');
            elements.modalContent.classList.add('scale-100', 'opacity-100');
        }, 10);
    }
}

function closeDetailModal() {
    // Defined in HTML script block, but included here for tool context:
    if (elements.detailModal && !elements.detailModal.classList.contains('hidden')) {
        const modalContent = elements.modalContent;
        modalContent.classList.remove('scale-100', 'opacity-100');
        modalContent.classList.add('scale-95', 'opacity-0');
        const filterInput = elements.modalArrayContent.querySelector('#modalArrayFilter');
        if(filterInput) filterInput.value = '';
        setTimeout(() => elements.detailModal.classList.add('hidden'), 300);
    }
}


// --- UTILITY FUNCTIONS ---

function createBadge(text, className, iconClass = 'fa-solid fa-circle') {
    const span = document.createElement('span');
    span.className = `inline-flex items-center px-3 py-1 text-[10px] font-bold rounded-full ${className} shadow-sm`;
    
    const icon = document.createElement('i');
    icon.className = `${iconClass} w-3 h-3 mr-1`;
    span.appendChild(icon);
    
    span.appendChild(document.createTextNode(text));
    return span;
}

/**
 * Utility to highlight wildcards in a URL match pattern and determine a corresponding group/icon.
 */
function highlightUrlPattern(pattern) {
    let highlightedHTML = pattern
        .replace(/\*/g, '<span class="text-red-400 font-bold">*</span>')
        .replace(/(\w+):\/\//g, '<span class="text-blue-400">$1://</span>')
        .replace(/<all_urls>/g, '<span class="text-red-500 font-extrabold">ALL_URLS</span>');

    let group = 'Specific Host';
    let example = 'N/A';
    
    if (pattern.includes('<all_urls>')) {
        group = 'Global Access (CRITICAL)';
        example = 'http://anydomain.com/anypath';
    } else if (pattern.includes('://*/*')) {
        group = 'All Hosts';
        example = 'https://google.com/search?q=test';
    } else if (pattern.startsWith('*://*')) {
        group = 'Any Protocol/Host';
        // Attempt to create a simple example URL
        try {
            const hostPart = pattern.split('//')[1] || '';
            const staticHost = hostPart.split('/')[0].replace(/\*/g, 'www');
            const pathPart = hostPart.split('/').slice(1).join('/');
            example = `https://${staticHost || 'example.com'}/${pathPart || 'index.html'}`;
        } catch (e) {
             example = 'N/A';
        }
    } else {
        // Specific Pattern. Attempt to create a simple example URL
        example = pattern.replace(/</g, '').replace(/>/g, '').replace(/\*/g, 'example');
    }
    
    return { highlightedHTML, group, example };
}

function displayRawJson(jsonString) {
    let formattedJson = jsonString;
    try {
        formattedJson = JSON.stringify(JSON.parse(jsonString), null, 2);
    } catch (e) {
        // Use raw string if formatting fails
    }
    
    codeMirrorEditor.setValue(formattedJson);
    codeMirrorEditor.setOption('readOnly', true);
    codeMirrorEditor.refresh();
}

function copyJson() {
    if (!currentManifest) {
        return showToast('No manifest loaded to copy.', 'border-red-500', 'Please upload a file first.');
    }
    try {
        const jsonString = codeMirrorEditor.getValue();
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(jsonString);
        } else {
            const tempTextArea = document.createElement('textarea');
            tempTextArea.value = jsonString;
            document.body.appendChild(tempTextArea);
            tempTextArea.select();
            document.execCommand('copy');
            document.body.removeChild(tempTextArea);
        }

        showToast('Raw JSON copied to clipboard!', 'border-green-500', null);
    } catch (e) {
        showToast('Copy failed.', 'border-red-500', 'Browser clipboard access denied.');
    }
}

function showToast(msg, borderColor, subMsg = null) {
    if (arguments.length === 2 && !borderColor.startsWith('border-')) {
        subMsg = borderColor;
        borderColor = 'border-blue-500'; 
    } else if (arguments.length === 2) {
        subMsg = null;
    }
    
    const t = elements.toast;
    
    let iconClass = 'fa-solid fa-info-circle text-blue-400';
    if(borderColor.includes('red')) iconClass = 'fa-solid fa-triangle-exclamation text-red-400';
    if(borderColor.includes('green')) iconClass = 'fa-solid fa-check-circle text-green-400';
    
    elements.toastIcon.className = iconClass;
    
    elements.toastMsg.innerHTML = subMsg ? 
        `<span class="font-bold">${msg.trim()}</span> <span class="text-gray-400 font-normal ml-2 text-xs">${subMsg.trim()}</span>` : 
        `<span class="font-bold">${msg.trim()}</span>`;
        
    t.className = `fixed bottom-6 right-6 px-4 py-3 rounded bg-gray-800 shadow-2xl text-white font-medium text-sm transform transition-all duration-300 z-[100] flex items-center gap-3 border-l-4 ${borderColor}`;
    
    t.classList.remove('translate-y-20', 'opacity-0');
    
    setTimeout(() => t.classList.add('translate-y-20', 'opacity-0'), 4000);
}
