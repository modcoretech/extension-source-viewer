// viewer.js
// Requires JSZip to handle CRX extraction
// Include JSZip via CDN
const script = document.createElement('script');
script.src = "https://cdnjs.cloudflare.com/ajax/libs/jszip/3.11.0/jszip.min.js";
document.head.appendChild(script);

script.onload = () => {
    const crxInput = document.getElementById('crxInput');
    const fileList = document.getElementById('fileList');
    const fileContent = document.getElementById('fileContent');

    crxInput.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        fileList.innerHTML = "Loading CRX...";

        const buffer = await file.arrayBuffer();

        // CRX Header parsing (CRXv2/v3)
        // Skip the header and extract zip portion
        let zipStart = 0;
        const magic = new Uint8Array(buffer.slice(0, 4));
        if (magic[0] !== 67 || magic[1] !== 82 || magic[2] !== 67 || magic[3] !== 0x21) {
            alert("Not a valid CRX file");
            return;
        }

        // CRX v2 header size: 16 + public key length + signature length
        const dv = new DataView(buffer);
        const version = dv.getUint32(4, true);
        if (version === 2) {
            const publicKeyLength = dv.getUint32(8, true);
            const signatureLength = dv.getUint32(12, true);
            zipStart = 16 + publicKeyLength + signatureLength;
        } else if (version === 3) {
            // CRXv3 uses a header size field at 8
            const headerSize = dv.getUint32(8, true);
            zipStart = 12 + headerSize;
        } else {
            alert("Unsupported CRX version: " + version);
            return;
        }

        const zipData = buffer.slice(zipStart);

        const zip = await JSZip.loadAsync(zipData);
        fileList.innerHTML = "";

        // Populate file list
        Object.keys(zip.files).forEach(filename => {
            const item = document.createElement('div');
            item.textContent = filename;
            item.className = 'file-item';
            item.addEventListener('click', async () => {
                const content = await zip.files[filename].async('string');
                fileContent.textContent = content;
            });
            fileList.appendChild(item);
        });

        fileContent.textContent = "Select a file to view its content...";
    });
};
