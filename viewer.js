// --- CONFIGURATION ---
// CodeMirror Modes mapping
const CM_MODES = {
    js: 'javascript',
    json: 'application/json',
    css: 'text/css',
    html: 'htmlmixed',
    htm: 'htmlmixed',
    xml: 'xml',
    svg: 'xml',
    md: 'markdown',
    wat: 'text/x-csrc', // WebAssembly Text Format
    ttf: 'text/plain', // Font files usually cannot be displayed as text
    woff: 'text/plain',
    woff2: 'text/plain',
};

// --- GLOBAL STATE & EDITOR ---
let zip;
const fileMap = {}; // Maps full path to JSZip object
let currentFileName = '';
let originalFileContent = ''; 
let codeMirrorEditor; // The global CodeMirror instance

// --- DOM ELEMENTS ---
const treeRoot = document.getElementById('fileTree');
const crxInput = document.getElementById('crxInput');
const processBtn = document.getElementById('processBtn');
const searchBox = document.getElementById('searchBox');
const exportBtn = document.getElementById('exportBtn');
const downloadBtn = document.getElementById('downloadBtn');
const unminifyBtn = document.getElementById('unminifyBtn');
const copyFileBtn = document.getElementById('copyFileBtn');
const viewerHeader = document.getElementById('viewerHeader');
const currentFileNameDisplay = document.getElementById('currentFileNameDisplay');
const editorContainer = document.getElementById('editorContainer');
const mediaViewer = document.getElementById('mediaViewer');
const initialMessage = document.getElementById('initialMessage');
const treePlaceholder = document.getElementById('treePlaceholder');
const statusBar = document.getElementById('statusBar');
const cursorLine = document.getElementById('cursorLine');
const cursorCol = document.getElementById('cursorCol');
const toast = document.getElementById('toast');

// --- FIXED LAYOUT ADJUSTMENTS ---
// Removed resizer logic completely.

// --- INITIALIZATION ---

/**
 * Initializes the CodeMirror editor on load.
 */
function initCodeMirror() {
    codeMirrorEditor = CodeMirror(editorContainer, {
        value: "Select a file to begin inspection.",
        mode: "javascript",
        theme: "dracula",
        lineNumbers: true,
        readOnly: 'nocursor',
        matchBrackets: true,
        autoCloseBrackets: true,
        // Performance option for large files
        viewportMargin: Infinity 
    });

    // Update status bar on cursor activity
    codeMirrorEditor.on("cursorActivity", () => {
        const cursor = codeMirrorEditor.getCursor();
        cursorLine.textContent = cursor.line + 1;
        cursorCol.textContent = cursor.ch + 1;
    });
}

// Ensure CodeMirror is ready before initialization
window.onload = () => {
    initCodeMirror();
    if (!zip) treePlaceholder.style.display = 'block';
};

// --- CORE FUNCTIONS ---

/**
 * Handles the CRX/ZIP file processing.
 */
processBtn.onclick = async () => {
  if (!crxInput.files[0]) return showToast('Error: Select a CRX or ZIP file first.', 'bg-red-600');
  
  // Reset state
  zip = null;
  Object.keys(fileMap).forEach(key => delete fileMap[key]);
  currentFileName = '';
  originalFileContent = '';
  
  treeRoot.textContent = ''; 
  treePlaceholder.style.display = 'none';

  try {
    showToast('Analyzing file...', 'bg-blue-600', 10000);
    const arrayBuffer = await crxInput.files[0].arrayBuffer();
    zip = await JSZip.loadAsync(arrayBuffer);
    buildTree(zip.files, treeRoot);
    initialMessage.style.display = 'flex';
    viewerHeader.classList.add('hidden');
    hideViewerContent();
    codeMirrorEditor.setValue('Select a file from the tree to view its contents.');
    showToast('File analyzed successfully. Structure loaded.', 'bg-green-600');
  } catch (error) {
    displayError('Processing Error', `Failed to analyze file: ${error.message}`);
    treePlaceholder.style.display = 'block';
  }
};

/**
 * Recursively builds the file tree structure.
 */
function buildTree(files, parentElement) {
  const items = {};
  for (const path in files) {
    if (path.endsWith('/') || files[path].dir) continue;

    const parts = path.split('/');
    let current = items;
    for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        const isFile = i === parts.length - 1;

        if (isFile) {
            current[part] = { isDir: false, path: path };
            fileMap[path] = files[path];
        } else {
            if (!current[part]) {
                current[part] = { isDir: true, path: parts.slice(0, i + 1).join('/') + '/', children: {} };
            }
            current = current[part].children;
        }
    }
  }

  const renderItem = (name, item, parent) => {
    const li = document.createElement('li');
    li.setAttribute('role', item.isDir ? 'group' : 'treeitem');
    
    if (item.isDir) {
      li.className = "space-y-1 font-semibold text-gray-300";
      const folderLabel = document.createElement('div');
      folderLabel.textContent = `📁 ${name}/`;
      folderLabel.className = 'cursor-pointer p-1 rounded tree-node-label transition-all duration-150';
      
      const ul = document.createElement('ul');
      ul.className = "ml-4 space-y-1 hidden";
      
      folderLabel.onclick = () => ul.classList.toggle('hidden');
      folderLabel.onkeypress = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); ul.classList.toggle('hidden'); } };
      folderLabel.setAttribute('tabindex', '0');
      li.appendChild(folderLabel);
      li.appendChild(ul);
      parent.appendChild(li);

      Object.keys(item.children)
        .sort((a, b) => {
          const aIsDir = item.children[a].isDir;
          const bIsDir = item.children[b].isDir;
          if (aIsDir === bIsDir) return a.localeCompare(b);
          return aIsDir ? -1 : 1;
        })
        .forEach(childName => {
          renderItem(childName, item.children[childName], ul);
        });

    } else {
      const displayName = name;
      li.textContent = `${getFileIcon(displayName)} ${displayName}`;
      li.className = "cursor-pointer p-1 rounded tree-node-label transition-all duration-150";
      li.setAttribute('tabindex', '0');
      li.setAttribute('data-path', item.path);
      li.onclick = () => showFile(item.path, li);
      li.onkeypress = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); showFile(item.path, li); } };
      parent.appendChild(li);
    }
  };
  
  const ul = document.createElement('ul');
  ul.setAttribute('role', 'tree');
  Object.keys(items).sort((a, b) => {
    const aIsDir = items[a].isDir;
    const bIsDir = items[b].isDir;
    if (aIsDir === bIsDir) return a.localeCompare(b);
    return aIsDir ? -1 : 1;
  }).forEach(rootName => {
    renderItem(rootName, items[rootName], ul);
  });
  parentElement.appendChild(ul);
}

function getFileIcon(fileName) {
    if (fileName.endsWith('.js')) return '📜';
    if (fileName.match(/\.(png|jpe?g|gif|webp|ico|svg)$/i)) return '🖼️';
    if (fileName.endsWith('.json')) return '⚙️';
    if (fileName.endsWith('.css')) return '🎨';
    if (fileName.endsWith('.html') || fileName.endsWith('.htm')) return '🌐';
    if (fileName.endsWith('.wasm')) return '🚀';
    if (fileName.match(/\.(ttf|woff|woff2)$/i)) return '🔤';
    return '📄';
}

function getCodeMirrorMode(fileName) {
    const ext = fileName.split('.').pop().toLowerCase();
    return CM_MODES[ext] || 'text/plain';
}

/**
 * Clears and hides all viewer content elements.
 */
function hideViewerContent() {
    editorContainer.classList.add('hidden');
    mediaViewer.classList.add('hidden');
    statusBar.classList.add('hidden');
    mediaViewer.textContent = '';
    unminifyBtn.classList.add('hidden');
}

/**
 * Shows the content of a selected file using CodeMirror or media viewer.
 */
async function showFile(name, li) {
  currentFileName = name;
  viewerHeader.classList.remove('hidden');
  currentFileNameDisplay.textContent = name;
  initialMessage.style.display = 'none';
  hideViewerContent();
  
  document.querySelectorAll('#fileTree li').forEach(i => i.classList.remove('file-active'));
  li.classList.add('file-active');

  const file = fileMap[name];
  if (!file) {
    return displayError('File Load Error', `Content for path '${name}' could not be found.`);
  }
  
  const ext = name.split('.').pop().toLowerCase();

  // Handle media files (Images and SVGs)
  if (['png', 'jpg', 'jpeg', 'gif', 'webp', 'ico', 'svg'].includes(ext)) {
    try {
      showToast('Loading media...', 'bg-blue-600', 1000);
      if (ext === 'svg') {
        const content = await file.async('text');
        mediaViewer.innerHTML = content;
      } else {
        const mimeType = `image/${ext === 'jpg' ? 'jpeg' : ext}`;
        const blob = await file.async('blob');
        const url = URL.createObjectURL(blob);
        const img = document.createElement('img');
        img.src = url;
        img.alt = name;
        img.className = 'max-w-full max-h-full object-contain';
        mediaViewer.appendChild(img);
        img.onload = () => URL.revokeObjectURL(url);
      }
      mediaViewer.classList.remove('hidden');
      originalFileContent = 'MEDIA_FILE';
      showToast('Media loaded.', 'bg-green-600');
    } catch (e) {
      displayError('Media Render Error', `Could not render file: ${e.message}`);
    }
  } else {
    // Handle code/text files with CodeMirror (including font file placeholders)
    try {
      showToast('Loading source code...', 'bg-blue-600', 10000);
      const content = await file.async('string');
      
      const mode = getCodeMirrorMode(name);
      
      if (mode === 'text/plain' && file.uncompressedSize > 50000) {
           // For large binary or unknown files, show a message instead of crashing
           originalFileContent = `/* File is too large or is a binary format (.${ext}). Content display skipped for performance. */\n\nFile Size: ${formatBytes(file.uncompressedSize)}`;
      } else {
           originalFileContent = content;
      }

      codeMirrorEditor.setOption("mode", mode);
      codeMirrorEditor.setValue(originalFileContent);
      codeMirrorEditor.setOption("readOnly", true);
      editorContainer.classList.remove('hidden');
      statusBar.classList.remove('hidden');
      codeMirrorEditor.refresh(); 

      if (ext === 'js') {
        unminifyBtn.classList.remove('hidden');
      }
      showToast('File loaded into editor.', 'bg-green-600');
      
    } catch (e) {
      displayError('Content Read Error', `Failed to read file content: ${e.message}`);
    }
  }
}

// --- FEATURES ---

/**
 * File path search functionality (Fix: Tree filtering only).
 */
searchBox.oninput = () => {
  const q = searchBox.value.toLowerCase().trim();
  
  // Filter all file items in the tree
  document.querySelectorAll('#fileTree li[data-path]').forEach(li => {
    const path = li.getAttribute('data-path');
    if (path && path.toLowerCase().includes(q)) {
      li.style.display = 'block';
      
      // Keep parent folders visible (Unfold if needed)
      let parentUL = li.closest('ul');
      while(parentUL && parentUL.previousElementSibling && parentUL.previousElementSibling.tagName === 'DIV') {
          if (parentUL.classList.contains('hidden')) {
              parentUL.classList.remove('hidden'); 
          }
          parentUL = parentUL.parentElement.closest('ul');
      }
    } else {
      li.style.display = 'none';
    }
  });
};

/**
 * Handles the Prettify/Unminify toggle for JavaScript.
 */
unminifyBtn.onclick = () => {
    
    const isPrettifying = unminifyBtn.textContent.includes('Prettify');

    if (isPrettifying) {
        try {
            showToast('Prettifying code...', 'bg-blue-600', 1000);
            const prettyCode = window.js_beautify(originalFileContent, { 
                indent_size: 2, 
                space_in_empty_paren: true 
            });
            codeMirrorEditor.setValue(prettyCode);
            unminifyBtn.textContent = 'Minify/Original';
        } catch (e) {
            showToast('Prettify Error: Code is malformed or too complex.', 'bg-red-600');
        }
    } else {
        // Switch back to original content
        codeMirrorEditor.setValue(originalFileContent);
        unminifyBtn.textContent = 'Prettify Code';
    }
    codeMirrorEditor.refresh(); 
};

/**
 * Copies the current content to the clipboard.
 * Fix: Ignores copy for media files.
 */
copyFileBtn.onclick = async () => {
    if (originalFileContent === 'MEDIA_FILE') {
        return showToast('Error: Cannot copy content from a media file.', 'bg-red-600');
    }
    
    const contentToCopy = codeMirrorEditor.getValue();
    
    try {
        await navigator.clipboard.writeText(contentToCopy);
        copyFileBtn.textContent = 'Copied!';
        showToast('Content copied to clipboard!', 'bg-green-600');
        setTimeout(() => copyFileBtn.textContent = 'Copy Content', 1500);
    } catch (e) {
        showToast('Copy Error: Failed to copy to clipboard.', 'bg-red-600');
    }
};

// --- UTILITIES & ERROR HANDLING ---

/**
 * Simple error display in the viewer area.
 */
function displayError(title, message) {
    hideViewerContent();
    initialMessage.style.display = 'flex';
    initialMessage.innerHTML = `<svg class="w-16 h-16 mb-4 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg><p class="text-lg font-semibold text-red-400">${title}</p><p class="text-sm mt-2 text-gray-500">${message}</p>`;
    showToast(`${title}: ${message}`, 'bg-red-600');
}

/**
 * Displays a temporary, professional toast notification.
 */
let toastTimeout;
function showToast(message, bgColor, duration = 3000) {
    clearTimeout(toastTimeout);
    toast.textContent = message;
    toast.className = `toast-active ${bgColor}`;
    
    toastTimeout = setTimeout(() => {
        toast.classList.remove('toast-active');
    }, duration);
}

/**
 * Formats byte size into human-readable string.
 */
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}


// --- EXPORT & DOWNLOAD ---

exportBtn.onclick = async () => {
  if (!zip) return showToast('Error: No file loaded.', 'bg-red-600');
  try {
    showToast('Preparing ZIP export...', 'bg-blue-600', 5000);
    const blob = await zip.generateAsync({ type: 'blob' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'extracted_content.zip';
    a.click();
    URL.revokeObjectURL(url);
    showToast('Export successful!', 'bg-green-600');
  } catch (e) {
    showToast('Export Error: Failed to create ZIP file.', 'bg-red-600');
  }
};

downloadBtn.onclick = async () => {
  if (!currentFileName || !fileMap[currentFileName]) return showToast('Error: Select a file first.', 'bg-red-600');
  try {
    showToast(`Downloading ${currentFileName}...`, 'bg-blue-600', 1000);
    const content = await fileMap[currentFileName].async('blob');
    const url = URL.createObjectURL(content);
    const a = document.createElement('a');
    a.href = url;
    a.download = currentFileName.split('/').pop();
    a.click();
    URL.revokeObjectURL(url);
    showToast('Download successful!', 'bg-green-600');
  } catch (e) {
    showToast('Download Error: Failed to initiate file download.', 'bg-red-600');
  }
};
