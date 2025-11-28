// --- CONFIGURATION ---
const CM_MODES = {
    js: 'javascript', json: 'application/json', css: 'text/css',
    html: 'htmlmixed', htm: 'htmlmixed', xml: 'xml', svg: 'xml',
    md: 'markdown', txt: 'text/plain', php: 'application/x-httpd-php',
    py: 'text/x-python', java: 'text/x-java', c: 'text/x-csrc',
    ts: 'javascript', jsx: 'javascript', vue: 'htmlmixed'
};

const IMAGE_EXTS = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'ico', 'svg', 'bmp'];
const BINARY_LIMIT = 512 * 1024; // 512KB

// --- STATE ---
let zip = null;
const fileMap = {};
let tabs = [];
let activeTabPath = null;
let codeMirrorEditor;
let zoomLevel = 1;
let currentCtxPath = null;
let elements = {}; // Cached DOM elements

// --- INITIALIZATION ---

window.onload = () => {
    cacheElements();
    initSplit();
    initCodeMirror();
    initEventListeners();
};

function cacheElements() {
    // Robust element caching to prevent null errors
    const ids = [
        'fileTree', 'crxInput', 'searchBox', 'dropOverlay', 'loadingOverlay',
        'tabsContainer', 'tabsWrapper', 'editorWrapper', 'mediaViewer', 
        'mediaContainer', 'markdownViewer', 'welcomeScreen', 'noFileSelected',
        'editorToolbar', 'filePathDisplay', 'statusMsg', 'cursorLine', 
        'cursorCol', 'langDisplay', 'fileInfoPanel', 'infoSize', 'infoType',
        'exportBtn', 'copyFileBtn', 'unminifyBtn', 'markdownPreviewBtn',
        'zoomIn', 'zoomOut', 'resetZoom', 'heroUploadBtn', 'contextMenu',
        'ctxCopyPath', 'ctxDownload', 'toast', 'toastMsg', 'toastIcon',
        'treePlaceholder'
    ];
    
    ids.forEach(id => {
        elements[id] = document.getElementById(id);
        if(!elements[id]) console.warn(`Element #${id} missing from DOM`);
    });
}

function initSplit() {
    Split(['#sidebar', '#mainContent'], {
        sizes: [20, 80],
        minSize: [200, 400],
        gutterSize: 2,
        cursor: 'col-resize',
        gutter: (index, direction) => {
            const gutter = document.createElement('div');
            gutter.className = `gutter gutter-${direction}`;
            return gutter;
        }
    });
}

function initCodeMirror() {
    if (!elements.editorWrapper) return;
    
    codeMirrorEditor = CodeMirror(elements.editorWrapper, {
        mode: "javascript",
        theme: "dracula",
        lineNumbers: true,
        autoCloseBrackets: true,
        matchBrackets: true,
        foldGutter: true,
        gutters: ["CodeMirror-linenumbers", "CodeMirror-foldgutter"],
        styleActiveLine: true,
        lineWrapping: false,
        extraKeys: {
            "Ctrl-Space": "autocomplete", 
            "Ctrl-F": "findPersistent",
            "Cmd-F": "findPersistent"
        }
    });

    codeMirrorEditor.on("cursorActivity", () => {
        const cursor = codeMirrorEditor.getCursor();
        if(elements.cursorLine) elements.cursorLine.textContent = cursor.line + 1;
        if(elements.cursorCol) elements.cursorCol.textContent = cursor.ch + 1;
    });
}

function initEventListeners() {
    // File Inputs
    elements.crxInput.onchange = (e) => loadFile(e.target.files[0]);
    elements.heroUploadBtn.onclick = () => elements.crxInput.click();

    // Drag & Drop (Document)
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

    // Toolbar
    elements.exportBtn.onclick = exportAll;
    elements.copyFileBtn.onclick = copyContent;
    elements.unminifyBtn.onclick = togglePrettify;
    elements.markdownPreviewBtn.onclick = toggleMarkdownPreview;

    // Zoom
    elements.zoomIn.onclick = () => updateZoom(0.1);
    elements.zoomOut.onclick = () => updateZoom(-0.1);
    elements.resetZoom.onclick = () => { zoomLevel = 1; updateZoom(0); };

    // Search (Debounced)
    let searchTimeout;
    elements.searchBox.oninput = (e) => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => filterTree(e.target.value), 300);
    };

    // Context Menu
    document.addEventListener('click', () => elements.contextMenu.classList.add('hidden'));
    elements.contextMenu.onclick = (e) => e.stopPropagation(); // Keep open if clicking inside
    
    elements.ctxCopyPath.onclick = () => {
        navigator.clipboard.writeText(currentCtxPath);
        elements.contextMenu.classList.add('hidden');
        showToast('Path copied', 'border-green-500');
    };
    
    elements.ctxDownload.onclick = async () => {
        elements.contextMenu.classList.add('hidden');
        if(!currentCtxPath) return;
        const file = fileMap[currentCtxPath];
        const blob = await file.async('blob');
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = currentCtxPath.split('/').pop();
        a.click();
    };
}

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

// --- LOGIC ---

async function loadFile(file) {
    if (!file) return;

    elements.loadingOverlay.classList.remove('hidden');
    
    // Slight delay to ensure UI updates
    setTimeout(async () => {
        try {
            // Reset App State completely
            Object.keys(fileMap).forEach(k => delete fileMap[k]);
            tabs = [];
            activeTabPath = null;
            elements.fileTree.innerHTML = '';
            elements.searchBox.value = '';
            
            // Read Zip
            const arrayBuffer = await file.arrayBuffer();
            zip = await JSZip.loadAsync(arrayBuffer);
            
            // Build UI
            buildTree(zip.files, elements.fileTree);
            
            elements.treePlaceholder.style.display = 'none';
            elements.welcomeScreen.classList.add('hidden');
            elements.noFileSelected.classList.remove('hidden'); // Show "Select a file" state
            elements.fileInfoPanel.classList.add('hidden');
            
            renderTabs();
            showToast('Archive loaded successfully', 'border-green-500');
            
        } catch (e) {
            console.error(e);
            showToast('Error: Not a valid ZIP/CRX', 'border-red-500');
            elements.treePlaceholder.style.display = 'flex';
            elements.welcomeScreen.classList.remove('hidden');
            elements.noFileSelected.classList.add('hidden');
        } finally {
            elements.loadingOverlay.classList.add('hidden');
        }
    }, 100);
}

// --- TREE VIEW (Recursive) ---

function buildTree(files, container) {
    const root = { name: 'root', isDir: true, children: {}, path: '' };
    
    Object.keys(files).forEach(path => {
        // Fix: JSZip folders end with /, but we handle paths manually
        if (files[path].dir) return; 

        const parts = path.split('/');
        let current = root;
        
        parts.forEach((part, i) => {
            const isFile = i === parts.length - 1;
            if (!current.children[part]) {
                current.children[part] = {
                    name: part,
                    isDir: !isFile,
                    path: parts.slice(0, i+1).join('/'),
                    children: {},
                    fileObj: isFile ? files[path] : null
                };
            }
            current = current.children[part];
        });
        
        fileMap[path] = files[path];
    });

    renderTreeNodes(root.children, container);
}

function renderTreeNodes(children, parentElement) {
    const sortedKeys = Object.keys(children).sort((a, b) => {
        if (children[a].isDir === children[b].isDir) return a.localeCompare(b);
        return children[a].isDir ? -1 : 1;
    });

    const ul = document.createElement('ul');
    ul.className = 'pl-2 border-l border-gray-700 ml-2 space-y-0.5';
    if(parentElement === elements.fileTree) ul.className = 'space-y-0.5';

    sortedKeys.forEach(key => {
        const item = children[key];
        const li = document.createElement('li');
        li.dataset.treePath = item.path; // Identifier for Search

        const div = document.createElement('div');
        div.className = 'tree-node';
        div.tabIndex = 0;
        div.dataset.path = item.path; // Identifier for Click

        // Icons
        const iconClass = item.isDir 
            ? 'fa-solid fa-folder text-blue-400' 
            : `fa-regular ${getFileIcon(item.name)}`;
            
        div.innerHTML = `<i class="${iconClass} w-4 text-center"></i><span class="truncate">${item.name}</span>`;
        
        // Interaction
        div.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            currentCtxPath = item.path;
            elements.contextMenu.style.top = `${e.clientY}px`;
            elements.contextMenu.style.left = `${e.clientX}px`;
            elements.contextMenu.classList.remove('hidden');
        });

        if (item.isDir) {
            const childrenContainer = document.createElement('div');
            childrenContainer.className = 'hidden'; // Collapsed by default
            renderTreeNodes(item.children, childrenContainer);
            li.appendChild(div);
            li.appendChild(childrenContainer);

            // Toggle Logic
            const toggle = () => {
                const isHidden = childrenContainer.classList.contains('hidden');
                childrenContainer.classList.toggle('hidden');
                const icon = div.querySelector('i');
                icon.className = isHidden 
                    ? 'fa-solid fa-folder-open text-blue-300 w-4 text-center' 
                    : 'fa-solid fa-folder text-blue-400 w-4 text-center';
            };
            div.onclick = toggle;
            div.onkeydown = (e) => {
                if (e.key === 'Enter') toggle();
                if (e.key === 'ArrowRight') { e.preventDefault(); childrenContainer.classList.remove('hidden'); }
                if (e.key === 'ArrowLeft') { e.preventDefault(); childrenContainer.classList.add('hidden'); }
            };

        } else {
            li.appendChild(div);
            div.onclick = () => openFile(item.path);
            div.onkeydown = (e) => { if (e.key === 'Enter') openFile(item.path); };
        }
        
        ul.appendChild(li);
    });

    parentElement.appendChild(ul);
}

// --- SEARCH LOGIC (Recursive & Expanding) ---

function filterTree(query) {
    query = query.toLowerCase().trim();
    const roots = elements.fileTree.children[0] ? Array.from(elements.fileTree.children[0].children) : [];
    
    if (!query) {
        // Reset: Show all LI, Hide all folder containers (reset to collapsed state ideally, or just show visible)
        document.querySelectorAll('#fileTree li').forEach(li => li.style.display = 'block');
        document.querySelectorAll('.highlight-match').forEach(el => el.classList.remove('highlight-match'));
        return;
    }

    // Recursive function returns true if this node OR any child matches
    function processNode(li) {
        const div = li.querySelector('.tree-node');
        const path = li.dataset.treePath || '';
        const name = path.split('/').pop().toLowerCase();
        
        let match = name.includes(query);
        let childMatch = false;

        // Visual Highlight
        if (match) div.classList.add('highlight-match');
        else div.classList.remove('highlight-match');

        const childrenContainer = li.querySelector('div:not(.tree-node)'); // The container for sub-UL
        
        if (childrenContainer) {
            // It's a folder
            const childrenLIs = Array.from(childrenContainer.querySelectorAll(':scope > ul > li'));
            for (let childLI of childrenLIs) {
                if (processNode(childLI)) {
                    childMatch = true;
                }
            }
            
            // If a child matches, we MUST be visible and expanded
            if (childMatch) {
                childrenContainer.classList.remove('hidden');
                // Update icon to open
                div.querySelector('i').className = 'fa-solid fa-folder-open text-blue-300 w-4 text-center';
            } else if (!match) {
                // If no child match and I don't match, hide container
                 childrenContainer.classList.add('hidden');
            }
        }

        const shouldShow = match || childMatch;
        li.style.display = shouldShow ? 'block' : 'none';
        
        return shouldShow;
    }

    roots.forEach(processNode);
}

// --- TABS & CONTENT ---

function openFile(path) {
    // 1. Highlight in Tree
    document.querySelectorAll('.tree-node').forEach(n => n.classList.remove('active'));
    const node = document.querySelector(`.tree-node[data-path="${path}"]`);
    if(node) node.classList.add('active');

    // 2. Add to tabs if not present
    if (!tabs.find(t => t.path === path)) {
        tabs.push({ path: path, content: null, scrollInfo: null });
    }

    // 3. Update File Info
    const file = fileMap[path];
    if(file) {
        elements.infoSize.textContent = formatBytes(file._data.uncompressedSize);
        elements.infoType.textContent = path.split('.').pop().toUpperCase();
        elements.fileInfoPanel.classList.remove('hidden');
    }

    activateTab(path);
}

function closeTab(path, e) {
    if(e) e.stopPropagation();
    
    const idx = tabs.findIndex(t => t.path === path);
    if(idx === -1) return;

    tabs.splice(idx, 1);

    if (tabs.length === 0) {
        // No tabs left: Show "No File Selected" state
        activeTabPath = null;
        renderTabs();
        elements.tabsWrapper.classList.add('hidden');
        elements.editorToolbar.classList.add('hidden');
        elements.editorWrapper.classList.add('hidden');
        elements.mediaViewer.classList.add('hidden');
        elements.markdownViewer.classList.add('hidden');
        elements.noFileSelected.classList.remove('hidden'); // Fix: Don't show Welcome, show Empty State
    } else {
        // Switch to adjacent tab if we closed the active one
        if (path === activeTabPath) {
            const nextPath = tabs[idx] ? tabs[idx].path : tabs[idx - 1].path;
            activateTab(nextPath);
        } else {
            renderTabs(); // Just update list
        }
    }
}

async function activateTab(path) {
    activeTabPath = path;
    renderTabs();

    // UI Updates
    elements.noFileSelected.classList.add('hidden');
    elements.welcomeScreen.classList.add('hidden');
    elements.tabsWrapper.classList.remove('hidden');
    elements.editorToolbar.classList.remove('hidden');
    elements.filePathDisplay.textContent = path;
    
    // Hide all Specific Viewers
    elements.editorWrapper.classList.add('hidden');
    elements.mediaViewer.classList.add('hidden');
    elements.markdownViewer.classList.add('hidden');
    
    // Reset buttons
    elements.unminifyBtn.classList.add('hidden');
    elements.markdownPreviewBtn.classList.add('hidden');

    const file = fileMap[path];
    if (!file) return;

    const ext = path.split('.').pop().toLowerCase();
    const tabData = tabs.find(t => t.path === path);

    // --- Image Viewer ---
    if (IMAGE_EXTS.includes(ext)) {
        elements.mediaViewer.classList.remove('hidden');
        elements.statusMsg.textContent = 'Viewing Media';
        
        try {
            const blob = await file.async('blob');
            const url = URL.createObjectURL(blob);
            elements.mediaContainer.innerHTML = `<img src="${url}" class="max-w-none shadow-2xl rounded-sm">`;
            zoomLevel = 1;
            updateZoom(0);
        } catch(e) {
            elements.mediaContainer.textContent = "Error loading image.";
        }
        return;
    }

    // --- Text/Code Viewer ---
    elements.editorWrapper.classList.remove('hidden');
    elements.statusMsg.textContent = 'Editing';

    // Enable toolbar buttons based on ext
    if(['js','json','html','css'].includes(ext)) elements.unminifyBtn.classList.remove('hidden');
    if(ext === 'md') elements.markdownPreviewBtn.classList.remove('hidden');

    // Load content if first time
    if (tabData.content === null) {
        if (file._data.uncompressedSize > BINARY_LIMIT) {
             tabData.content = `// File is too large (${formatBytes(file._data.uncompressedSize)}) to preview automatically.\n// This prevents browser crashes.\n\n// You can download it using the button in the top right.`;
        } else {
             // For standard text
             try {
                tabData.content = await file.async('string');
             } catch(e) {
                 tabData.content = "// Error reading file text (might be binary).";
             }
        }
    }

    // CodeMirror Setup
    const mode = CM_MODES[ext] || 'text/plain';
    elements.langDisplay.textContent = mode.toUpperCase();
    
    codeMirrorEditor.setOption('mode', mode);
    codeMirrorEditor.setValue(tabData.content);
    codeMirrorEditor.clearHistory();
    
    if (tabData.scrollInfo) {
        codeMirrorEditor.scrollTo(tabData.scrollInfo.left, tabData.scrollInfo.top);
    }
}

function renderTabs() {
    const container = elements.tabsContainer;
    container.innerHTML = '';

    tabs.forEach(tab => {
        const isActive = tab.path === activeTabPath;
        const div = document.createElement('div');
        div.className = `tab-item ${isActive ? 'active' : ''}`;
        
        const name = tab.path.split('/').pop();
        
        div.innerHTML = `
            <i class="${getFileIcon(name)} text-[10px]"></i>
            <span class="truncate pt-0.5">${name}</span>
            <i class="fa-solid fa-times tab-close text-[10px] ml-auto"></i>
        `;

        div.onclick = () => {
             // Save scroll position of current before switching
            if(activeTabPath && !IMAGE_EXTS.includes(activeTabPath.split('.').pop())) {
                const curr = tabs.find(t => t.path === activeTabPath);
                if(curr) curr.scrollInfo = codeMirrorEditor.getScrollInfo();
            }
            activateTab(tab.path);
        };
        
        div.querySelector('.tab-close').onclick = (e) => closeTab(tab.path, e);
        
        container.appendChild(div);
        
        if(isActive) div.scrollIntoView({behavior: "smooth", block: "nearest"});
    });
}

// --- UTILS ---

function getFileIcon(filename) {
    if(filename.endsWith('js')) return 'fa-brands fa-js text-yellow-400';
    if(filename.endsWith('css')) return 'fa-brands fa-css3-alt text-blue-400';
    if(filename.endsWith('html')) return 'fa-brands fa-html5 text-orange-400';
    if(filename.endsWith('json')) return 'fa-solid fa-gear text-gray-400';
    if(filename.match(/\.(png|jpg|gif|svg)$/)) return 'fa-regular fa-image text-purple-400';
    return 'fa-regular fa-file text-gray-400';
}

function updateZoom(delta) {
    zoomLevel += delta;
    if (zoomLevel < 0.1) zoomLevel = 0.1;
    document.getElementById('mediaContainer').style.transform = `scale(${zoomLevel})`;
    document.getElementById('zoomLevelDisplay').textContent = `${Math.round(zoomLevel * 100)}%`;
}

function togglePrettify() {
    if(!activeTabPath) return;
    const content = codeMirrorEditor.getValue();
    try {
        const fmt = js_beautify(content);
        codeMirrorEditor.setValue(fmt);
    } catch(e) {
        showToast('Formatting failed', 'border-red-500');
    }
}

function toggleMarkdownPreview() {
    const mdDiv = elements.markdownViewer;
    const editor = elements.editorWrapper;
    
    if (mdDiv.classList.contains('hidden')) {
        mdDiv.innerHTML = marked.parse(codeMirrorEditor.getValue());
        mdDiv.classList.remove('hidden');
        editor.classList.add('hidden');
    } else {
        mdDiv.classList.add('hidden');
        editor.classList.remove('hidden');
    }
}

async function exportAll() {
    if(!zip) return showToast('No file loaded', 'border-red-500');
    showToast('Preparing ZIP...', 'border-blue-500');
    const content = await zip.generateAsync({type:"blob"});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(content);
    a.download = "extracted_extension.zip";
    a.click();
}

function copyContent() {
    const txt = codeMirrorEditor.getValue();
    navigator.clipboard.writeText(txt);
    showToast('Copied to clipboard', 'border-green-500');
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + ['B', 'KB', 'MB', 'GB'][i];
}

function showToast(msg, borderColor) {
    const t = elements.toast;
    elements.toastMsg.textContent = msg;
    t.className = `fixed bottom-6 right-6 px-4 py-3 rounded bg-gray-800 border-l-4 shadow-2xl text-white font-medium text-sm transform transition-all duration-300 z-[100] flex items-center gap-3 ${borderColor}`;
    
    t.classList.remove('translate-y-20', 'opacity-0');
    setTimeout(() => t.classList.add('translate-y-20', 'opacity-0'), 3000);
}
