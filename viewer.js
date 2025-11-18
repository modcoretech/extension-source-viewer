// viewer.js
let zip, fileMap = {};
const treeRoot = document.getElementById('treeRoot');
const viewer = document.getElementById('viewer');
const crxInput = document.getElementById('crxInput');
const processBtn = document.getElementById('processBtn');
const searchBox = document.getElementById('searchBox');
const themeToggle = document.getElementById('themeToggle');
const exportBtn = document.getElementById('exportBtn');

let currentTheme = 'dark';

// THEME TOGGLE
themeToggle.onclick = () => {
  if(currentTheme==='dark'){ document.body.classList.add('light'); currentTheme='light'; }
  else { document.body.classList.remove('light'); currentTheme='dark'; }
};

// PROCESS FILE
processBtn.onclick = async () => {
  if (!crxInput.files[0]) return alert('Please select a CRX file!');
  const arrayBuffer = await crxInput.files[0].arrayBuffer();
  zip = await JSZip.loadAsync(arrayBuffer);
  fileMap = {}; // clear previous
  treeRoot.innerHTML = '';
  buildTree(zip, treeRoot, '');
};

// BUILD TREE
async function buildTree(folder, parent, path) {
  for(const name in folder.files){
    const f = folder.files[name];
    const displayName = name.split('/').pop();
    if(f.dir){
      const li = document.createElement('li');
      li.textContent = displayName+'/';
      const ul = document.createElement('ul');
      li.appendChild(ul);
      parent.appendChild(li);
      buildTree(f, ul, name);
    } else {
      const li = document.createElement('li');
      li.textContent = displayName;
      li.onclick = async () => showFile(name, li);
      parent.appendChild(li);
      fileMap[name] = f;
    }
  }
}

// SHOW FILE CONTENT
async function showFile(name, li){
  const content = await zip.file(name).async('string');
  viewer.textContent = content;
  Prism.highlightElement(viewer);
  document.querySelectorAll('#fileTree li').forEach(i=>i.classList.remove('selected'));
  li.classList.add('selected');
}

// SEARCH FILES
searchBox.oninput = ()=>{
  const q = searchBox.value.toLowerCase();
  document.querySelectorAll('#fileTree li').forEach(li=>{
    if(li.textContent.toLowerCase().includes(q)) li.style.display='block';
    else li.style.display='none';
  });
}

// EXPORT SELECTED FILES
exportBtn.onclick = async ()=>{
  if(!zip) return alert('No CRX loaded!');
  const exportZip = new JSZip();
  for(const path in fileMap){
    const content = await zip.file(path).async('arraybuffer');
    exportZip.file(path, content);
  }
  const blob = await exportZip.generateAsync({type:'blob'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'extracted_extension.zip';
  a.click();
  URL.revokeObjectURL(url);
}
