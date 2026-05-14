/* ═══════════════════════════════════════════
   VENOM — Static Malware Analyzer
   Client-side analysis engine
   ═══════════════════════════════════════════ */

(() => {
    'use strict';

    // ─── DOM refs ───
    const dropZone       = document.getElementById('dropZone');
    const fileInput      = document.getElementById('fileInput');
    const uploadSection  = document.getElementById('upload-section');
    const resultsSection = document.getElementById('results-section');
    const fileMeta       = document.getElementById('fileMeta');
    const threatGauge    = document.getElementById('threatGauge');
    const gaugeFill      = document.getElementById('gaugeFill');
    const threatLabel    = document.getElementById('threatLabel');
    const threatScore    = document.getElementById('threatScore');
    const threatTags     = document.getElementById('threatTags');
    const detectionsList = document.getElementById('detectionsList');
    const detectionCount = document.getElementById('detectionCount');
    const webhooksCard   = document.getElementById('webhooksCard');
    const webhooksList   = document.getElementById('webhooksList');
    const webhookCount   = document.getElementById('webhookCount');
    const stringsList    = document.getElementById('stringsList');
    const stringCount    = document.getElementById('stringCount');
    const stringsFilter  = document.getElementById('stringsFilter');
    const jarCard        = document.getElementById('jarCard');
    const jarFileCount   = document.getElementById('jarFileCount');
    const jarMetaRow     = document.getElementById('jarMetaRow');
    const jarTree        = document.getElementById('jarTree');
    const newScanBtn     = document.getElementById('newScanBtn');
    const toastContainer = document.getElementById('toastContainer');

    // ─── Drag & drop ───
    ['dragenter', 'dragover'].forEach(evt => {
        dropZone.addEventListener(evt, e => {
            e.preventDefault();
            dropZone.classList.add('drag-over');
        });
    });

    ['dragleave', 'drop'].forEach(evt => {
        dropZone.addEventListener(evt, e => {
            e.preventDefault();
            dropZone.classList.remove('drag-over');
        });
    });

    dropZone.addEventListener('drop', e => {
        const files = e.dataTransfer.files;
        if (files.length) analyzeFile(files[0]);
    });

    dropZone.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', () => {
        if (fileInput.files.length) analyzeFile(fileInput.files[0]);
    });

    newScanBtn.addEventListener('click', resetUI);

    // ─── Helpers ───
    function toast(msg, type = 'info') {
        const el = document.createElement('div');
        el.className = `toast ${type}`;
        el.textContent = msg;
        toastContainer.appendChild(el);
        setTimeout(() => el.remove(), 3600);
    }

    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    async function sha256(buffer) {
        const hash = await crypto.subtle.digest('SHA-256', buffer);
        return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    async function md5ish(buffer) {
        const hash = await crypto.subtle.digest('SHA-1', buffer);
        return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    function extractStrings(uint8Array, minLen = 4) {
        const strings = [];
        let current = '';
        for (let i = 0; i < uint8Array.length; i++) {
            const byte = uint8Array[i];
            if (byte >= 32 && byte <= 126) {
                current += String.fromCharCode(byte);
            } else {
                if (current.length >= minLen) strings.push(current);
                current = '';
            }
        }
        if (current.length >= minLen) strings.push(current);
        return strings;
    }

    function calcEntropy(uint8Array) {
        const freq = new Array(256).fill(0);
        for (let i = 0; i < uint8Array.length; i++) freq[uint8Array[i]]++;
        let entropy = 0;
        const len = uint8Array.length;
        for (let i = 0; i < 256; i++) {
            if (freq[i] === 0) continue;
            const p = freq[i] / len;
            entropy -= p * Math.log2(p);
        }
        return entropy;
    }

    function getFileExtension(name) {
        const parts = name.split('.');
        return parts.length > 1 ? '.' + parts.pop().toLowerCase() : 'unknown';
    }

    // ─── Detection rules ───
    const DETECTION_RULES = [
        // Networking / exfil
        { name: 'HTTP Request Library',       severity: 'low',      pattern: /(?:requests\.(?:get|post)|urllib|httplib|fetch\(|XMLHttpRequest|axios|http\.client|WebClient|Invoke-WebRequest|curl_exec)/gi, desc: 'Uses HTTP networking — common in data exfiltration' },
        { name: 'Socket / Raw Network',       severity: 'low',      pattern: /(?:socket\.socket|SOCK_STREAM|SOCK_DGRAM|WSAStartup|connect\(|bind\(|listen\(|accept\()/gi, desc: 'Raw socket operations — could be C2 communication' },
        { name: 'DNS Query',                  severity: 'low',      pattern: /(?:dns\.resolver|nslookup|Resolve-DnsName|getaddrinfo)/gi, desc: 'DNS resolution — may be used for DNS tunneling or C2' },

        // Discord specific
        { name: 'Discord Webhook URL',        severity: 'critical', pattern: /https?:\/\/(?:discord\.com|discordapp\.com)\/api\/webhooks\/\d+\/[\w-]+/gi, desc: 'Discord webhook URL — used for data exfiltration to Discord' },
        { name: 'Discord Token Theft',        severity: 'critical', pattern: /(?:discord.*token|token.*discord|leveldb|Local Storage.*discord)/gi, desc: 'Possible Discord token harvesting' },
        { name: 'Discord API Reference',      severity: 'medium',   pattern: /(?:discord\.com\/api|discordapp\.com\/api|discord\.gg)/gi, desc: 'References Discord API — may interact with Discord services' },

        // Credential / browser theft
        { name: 'Browser Data Theft',         severity: 'critical', pattern: /(?:Login Data|Cookies|Web Data|Local State|chrome|firefox|brave|opera|edge).*(?:sqlite|leveldb|json)/gi, desc: 'Targets browser storage — credential or cookie theft' },
        { name: 'Crypto Wallet Target',       severity: 'critical', pattern: /(?:wallet\.dat|exodus|metamask|phantom|solflare|coinbase.*wallet|electrum)/gi, desc: 'Targets cryptocurrency wallets' },
        { name: 'Password / Credential Keywords', severity: 'medium', pattern: /(?:passwd|credential|login.*data|keychain|vault)/gi, desc: 'References passwords or credentials' },

        // Persistence
        { name: 'Registry Modification',      severity: 'high',     pattern: /(?:RegSetValue|RegCreateKey|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE|Software\\Microsoft\\Windows\\CurrentVersion\\Run)/gi, desc: 'Modifies Windows registry — persistence mechanism' },
        { name: 'Startup Folder',             severity: 'high',     pattern: /(?:Startup|AppData\\Roaming\\Microsoft\\Windows\\Start Menu|shell:startup)/gi, desc: 'References startup folder — auto-run persistence' },
        { name: 'Scheduled Task',             severity: 'high',     pattern: /(?:schtasks|TaskScheduler|Register-ScheduledTask)/gi, desc: 'Creates scheduled tasks — timed persistence' },
        { name: 'Service Installation',       severity: 'high',     pattern: /(?:CreateService|sc create|New-Service|InstallUtil)/gi, desc: 'Installs as Windows service' },

        // Execution / injection
        { name: 'Process Injection',          severity: 'critical', pattern: /(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|QueueUserAPC)/gi, desc: 'Process injection APIs — code execution in another process' },
        { name: 'Shellcode / Memory Exec',    severity: 'critical', pattern: /(?:VirtualAlloc|VirtualProtect|RtlMoveMemory|PAGE_EXECUTE|MEM_COMMIT)/gi, desc: 'Memory allocation with execute permissions — shellcode loading' },
        { name: 'Dynamic Code Execution',     severity: 'high',     pattern: /(?:eval\(|exec\(|compile\(|__import__|importlib|ctypes\.windll|subprocess)/gi, desc: 'Dynamic code execution — can run arbitrary code' },
        { name: 'PowerShell Execution',       severity: 'high',     pattern: /(?:powershell|pwsh|Invoke-Expression|IEX|Set-ExecutionPolicy|Bypass|-enc\s)/gi, desc: 'PowerShell usage — common in fileless malware' },
        { name: 'CMD / Shell Spawn',          severity: 'medium',   pattern: /(?:cmd\.exe|command\.com|\/c\s|ShellExecute|WScript\.Shell|os\.system|os\.popen)/gi, desc: 'Spawns command shell' },

        // Evasion
        { name: 'Base64 Encoding',            severity: 'medium',   pattern: /(?:base64|b64decode|b64encode|atob|btoa|FromBase64String|ToBase64String)/gi, desc: 'Base64 operations — commonly used to obfuscate payloads' },
        { name: 'Anti-VM / Sandbox Detection',severity: 'high',     pattern: /(?:VMware|VirtualBox|QEMU|Sandbox|SbieDll|DbgUiRemoteBreakin|IsDebuggerPresent|CheckRemoteDebugger)/gi, desc: 'Anti-analysis checks — evades sandboxes and debuggers' },
        { name: 'Anti-Debug',                 severity: 'high',     pattern: /(?:IsDebuggerPresent|NtQueryInformationProcess|CheckRemoteDebuggerPresent|OutputDebugString)/gi, desc: 'Debugger detection — anti-analysis technique' },
        { name: 'String Obfuscation',         severity: 'medium',   pattern: /(?:chr\(\d+\)|\\x[0-9a-f]{2}|String\.fromCharCode|charCodeAt|XOR|rot13)/gi, desc: 'String obfuscation techniques' },
        { name: 'UPX / Packer Signature',     severity: 'medium',   pattern: /(?:UPX0|UPX1|UPX2|\.packed|PE\x00\x00)/gi, desc: 'Packed binary — contents may be hidden' },

        // Keylogging / spying
        { name: 'Keylogger API',              severity: 'critical', pattern: /(?:SetWindowsHookEx|GetAsyncKeyState|GetKeyState|WH_KEYBOARD|WH_KEYBOARD_LL|GetForegroundWindow)/gi, desc: 'Keyboard hooking — keylogger behavior' },
        { name: 'Screenshot Capture',         severity: 'high',     pattern: /(?:BitBlt|GetDC|PrintWindow|CopyFromScreen|Screenshot|pyautogui\.screenshot|ImageGrab)/gi, desc: 'Screen capture functionality' },
        { name: 'Webcam Access',              severity: 'high',     pattern: /(?:VideoCapture|cv2\.VideoCapture|capCreateCaptureWindow|getUserMedia.*video)/gi, desc: 'Webcam access — surveillance capability' },
        { name: 'Clipboard Access',           severity: 'medium',   pattern: /(?:GetClipboardData|SetClipboardData|OpenClipboard|pyperclip|clipboard)/gi, desc: 'Clipboard monitoring or manipulation' },

        // File operations
        { name: 'File Encryption',            severity: 'high',     pattern: /(?:AES|Fernet|CryptEncrypt|CryptDecrypt|ransomware|\.encrypted|\.locked)/gi, desc: 'Encryption operations — possible ransomware behavior' },
        { name: 'Mass File Operation',        severity: 'medium',   pattern: /(?:os\.walk|glob\.glob|Path\.rglob|FindFirstFile|FindNextFile|Directory\.GetFiles)/gi, desc: 'Recursive file enumeration — mass file operations' },

        // Networking specifics
        { name: 'IP Address Literal',         severity: 'low',      pattern: /(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g, desc: 'Hardcoded IP address' },
        { name: 'Telegram Bot API',           severity: 'high',     pattern: /(?:api\.telegram\.org|bot\d+:|t\.me\/)/gi, desc: 'Telegram API — alternate exfil channel' },
        { name: 'Pastebin / Hastebin',        severity: 'medium',   pattern: /(?:pastebin\.com|hastebin\.com|paste\.ee|ghostbin)/gi, desc: 'Paste service — could fetch payloads or exfil data' },
        
        // Minecraft RAT specific
        { name: 'Minecraft Session Stealer',  severity: 'critical', pattern: /(?:launcher_accounts\.json|launcher_profiles\.json|usercache\.json|microsoft_auth)/gi, desc: 'Targets Minecraft session tokens' },
        { name: 'WeedHack / Known RAT',       severity: 'critical', pattern: /(?:WeedHack|weedhack|SessionStealer|TokenGrabber|DiscordGrabber)/gi, desc: 'Known Minecraft RAT signature' }
    ];

    // ─── Main analysis ───
    async function analyzeFile(file) {
        toast('Analyzing file...', 'info');

        const buffer = await file.arrayBuffer();
        const uint8  = new Uint8Array(buffer);
        const hashSHA256 = await sha256(buffer);
        const hashSHA1   = await md5ish(buffer);
        const entropy    = calcEntropy(uint8);
        const ext        = getFileExtension(file.name);
        
        let strings = [];
        let jarFiles = [];
        let scoreBonus = 0;
        let jarClasses = 0;
        let isJar = ext === '.jar' || ext === '.zip';

        if (isJar && window.JSZip) {
            try {
                const zip = await JSZip.loadAsync(file);
                for (const [path, zipEntry] of Object.entries(zip.files)) {
                    if (zipEntry.dir) continue;
                    
                    const isClass = path.endsWith('.class');
                    if (isClass) jarClasses++;
                    
                    let suspicious = false;
                    const pathLower = path.toLowerCase();
                    if (pathLower.includes('weedhack') || pathLower.includes('sessionstealer') || pathLower.includes('tokengrabber')) {
                        suspicious = true;
                        scoreBonus += 25;
                    }

                    jarFiles.push({
                        path,
                        size: zipEntry._data ? zipEntry._data.uncompressedSize : 0,
                        isClass,
                        suspicious
                    });

                    // Extract strings from every file in the JAR
                    try {
                        const fileUint8 = await zipEntry.async('uint8array');
                        const fileStrings = extractStrings(fileUint8, 4);
                        strings.push(...fileStrings);
                    } catch (e) {} // skip unreadable
                }
            } catch (e) {
                toast('Failed to parse JAR: ' + e.message, 'error');
                strings = extractStrings(uint8, 4); // fallback to raw string extraction
            }
        } else {
            strings = extractStrings(uint8, 4);
        }

        // Full text for pattern matching (combine extracted strings)
        const fullText = strings.join('\n');

        // Run detections
        const detections = [];
        for (const rule of DETECTION_RULES) {
            rule.pattern.lastIndex = 0;
            const matches = fullText.match(rule.pattern);
            if (matches) {
                // Deduplicate matches
                const unique = [...new Set(matches)];
                detections.push({
                    name: rule.name,
                    severity: rule.severity,
                    desc: rule.desc,
                    matches: unique,
                    count: matches.length
                });
            }
        }

        // Extract Discord webhooks specifically
        const webhookRegex = /https?:\/\/(?:discord\.com|discordapp\.com)\/api\/webhooks\/\d+\/[\w-]+/gi;
        const webhooks = [...new Set((fullText.match(webhookRegex) || []))];

        // Also scan raw bytes for webhooks (in case strings extraction misses partial)
        const rawText = new TextDecoder('utf-8', { fatal: false }).decode(uint8);
        const rawWebhooks = [...new Set((rawText.match(webhookRegex) || []))];
        const allWebhooks = [...new Set([...webhooks, ...rawWebhooks])];

        // Calculate threat score
        let score = 0;
        const severityWeights = { critical: 30, high: 15, medium: 7, low: 3 };
        for (const d of detections) {
            score += severityWeights[d.severity] * Math.min(d.count, 3);
        }
        // Entropy bonus
        if (entropy > 7.2) score += 15;
        else if (entropy > 6.5) score += 5;
        // Webhook bonus
        score += allWebhooks.length * 25;
        // Apply JAR specific bonuses
        score += scoreBonus;
        score = Math.min(score, 100);

        // Render
        renderFileMeta(file, hashSHA256, hashSHA1, entropy, ext, strings.length);
        renderThreatGauge(score, detections);
        renderDetections(detections);
        renderWebhooks(allWebhooks);
        renderStrings(strings);
        
        if (isJar && jarFiles.length > 0) {
            renderJarCard(jarFiles, jarClasses);
        } else {
            jarCard.classList.add('hidden');
        }

        uploadSection.classList.add('hidden');
        resultsSection.classList.remove('hidden');
    }

    // ─── Renderers ───

    function renderJarCard(jarFiles, classesCount) {
        jarCard.classList.remove('hidden');
        jarFileCount.textContent = jarFiles.length + ' FILES';
        
        const suspCount = jarFiles.filter(f => f.suspicious).length;
        
        jarMetaRow.innerHTML = `
            <div class="jar-meta-tag"><span>Total Files:</span> ${jarFiles.length}</div>
            <div class="jar-meta-tag"><span>Classes:</span> ${classesCount}</div>
            <div class="jar-meta-tag"><span>Suspicious:</span> <b style="color:var(--accent-orange)">${suspCount}</b></div>
        `;
        
        jarFiles.sort((a, b) => {
            if (a.suspicious && !b.suspicious) return -1;
            if (!a.suspicious && b.suspicious) return 1;
            return a.path.localeCompare(b.path);
        });
        
        jarTree.innerHTML = jarFiles.map(f => {
            const icon = f.isClass ? '☕' : '📄';
            const cls = 'jar-tree-entry ' + (f.isClass ? 'class-entry' : 'resource-entry') + (f.suspicious ? ' suspicious-entry' : '');
            return `<div class="${cls}">
                <span class="jar-entry-icon">${icon}</span>
                <span class="jar-entry-name">${escapeHtml(f.path)}</span>
                <span class="jar-entry-size">${formatBytes(f.size || 0)}</span>
            </div>`;
        }).join('');
    }

    function renderFileMeta(file, sha256Hash, sha1Hash, entropy, ext, strCount) {
        const items = [
            { label: 'Filename',   value: file.name },
            { label: 'Size',       value: formatBytes(file.size) },
            { label: 'Type',       value: ext },
            { label: 'Entropy',    value: entropy.toFixed(4) + ' / 8.0' },
            { label: 'SHA-256',    value: sha256Hash, hash: true },
            { label: 'SHA-1',      value: sha1Hash, hash: true },
            { label: 'Strings',    value: strCount.toLocaleString() + ' extracted' },
            { label: 'Scanned',    value: new Date().toISOString().replace('T', ' ').slice(0, 19) },
        ];

        fileMeta.innerHTML = items.map(i => `
            <div class="meta-item">
                <div class="meta-label">${i.label}</div>
                <div class="meta-value${i.hash ? ' hash' : ''}">${i.value}</div>
            </div>
        `).join('');
    }

    function renderThreatGauge(score, detections) {
        let level, cls;
        if (score === 0)      { level = 'CLEAN';    cls = 'clean'; }
        else if (score <= 15) { level = 'LOW';      cls = 'low'; }
        else if (score <= 40) { level = 'MEDIUM';   cls = 'medium'; }
        else if (score <= 70) { level = 'HIGH';     cls = 'high'; }
        else                  { level = 'CRITICAL'; cls = 'critical'; }

        requestAnimationFrame(() => {
            gaugeFill.style.width = score + '%';
            gaugeFill.className = 'gauge-fill ' + cls;
            threatLabel.textContent = level;
            threatLabel.className = 'threat-label ' + cls;
            threatScore.textContent = score;
            threatScore.style.color = getComputedStyle(document.documentElement)
                .getPropertyValue(`--accent-${cls === 'clean' ? 'green' : cls === 'low' ? 'green' : cls === 'medium' ? 'yellow' : cls === 'high' ? 'orange' : 'red'}`);
        });

        // Tags
        const tags = [];
        const severities = { critical: 0, high: 0, medium: 0, low: 0 };
        for (const d of detections) severities[d.severity]++;

        if (severities.critical > 0) tags.push({ text: `${severities.critical} CRITICAL`, cls: 'danger' });
        if (severities.high > 0)     tags.push({ text: `${severities.high} HIGH`, cls: 'warn' });
        if (severities.medium > 0)   tags.push({ text: `${severities.medium} MEDIUM`, cls: 'info' });
        if (severities.low > 0)      tags.push({ text: `${severities.low} LOW`, cls: 'info' });
        if (score === 0)             tags.push({ text: 'NO THREATS', cls: 'safe' });

        threatTags.innerHTML = tags.map(t =>
            `<span class="threat-tag ${t.cls}">${t.text}</span>`
        ).join('');
    }

    function renderDetections(detections) {
        detectionCount.textContent = detections.length;

        if (detections.length === 0) {
            detectionsList.innerHTML = `
                <div class="no-detections">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                        <polyline points="22 4 12 14.01 9 11.01"/>
                    </svg>
                    <p>No suspicious patterns detected</p>
                </div>
            `;
            return;
        }

        // Sort by severity
        const order = { critical: 0, high: 1, medium: 2, low: 3 };
        detections.sort((a, b) => order[a.severity] - order[b.severity]);

        detectionsList.innerHTML = detections.map(d => `
            <div class="detection-item">
                <span class="detection-severity ${d.severity}">${d.severity.toUpperCase()}</span>
                <div class="detection-body">
                    <div class="detection-name">${d.name}</div>
                    <div class="detection-desc">${d.desc}</div>
                    <code class="detection-match">${escapeHtml(d.matches.slice(0, 3).join(' | '))}${d.matches.length > 3 ? ` (+${d.matches.length - 3} more)` : ''}</code>
                </div>
            </div>
        `).join('');
    }

    function renderWebhooks(webhooks) {
        if (webhooks.length === 0) {
            webhooksCard.classList.add('hidden');
            return;
        }

        webhooksCard.classList.remove('hidden');
        webhookCount.textContent = webhooks.length;

        webhooksList.innerHTML = webhooks.map((url, idx) => `
            <div class="webhook-item" id="webhook-${idx}">
                <div class="webhook-url">${escapeHtml(url)}</div>
                <button class="webhook-delete-btn" onclick="deleteWebhook('${escapeHtml(url)}', ${idx})" id="webhook-btn-${idx}">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="3 6 5 6 21 6"/>
                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                    </svg>
                    DELETE WEBHOOK
                </button>
            </div>
        `).join('');
    }

    // Global — delete webhook via Discord API
    window.deleteWebhook = async function(url, idx) {
        const btn = document.getElementById(`webhook-btn-${idx}`);
        if (btn.classList.contains('deleted') || btn.classList.contains('deleting')) return;

        btn.classList.add('deleting');
        btn.textContent = 'DELETING...';

        try {
            const res = await fetch(url, { method: 'DELETE' });

            if (res.ok || res.status === 204 || res.status === 404) {
                btn.classList.remove('deleting');
                btn.classList.add('deleted');
                btn.innerHTML = `
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="20 6 9 17 4 12"/>
                    </svg>
                    DELETED
                `;
                toast('Webhook destroyed successfully', 'success');
            } else {
                throw new Error(`HTTP ${res.status}`);
            }
        } catch (err) {
            btn.classList.remove('deleting');
            btn.textContent = 'RETRY DELETE';
            toast(`Failed to delete webhook: ${err.message}`, 'error');
        }
    };

    function renderStrings(strings) {
        stringCount.textContent = strings.length;
        let currentStrings = strings;

        const suspiciousPatterns = /(?:password|token|secret|webhook|discord|eval|exec|shell|admin|root|hack|inject|payload|exploit|malware|trojan|keylog|rat\b|stealer|grab)/i;
        const webhookPattern = /discord\.com\/api\/webhooks/i;

        function renderList(filtered) {
            // Limit display to 500 for performance
            const display = filtered.slice(0, 500);
            stringsList.innerHTML = display.map(s => {
                let cls = 'string-line';
                if (webhookPattern.test(s)) cls += ' webhook';
                else if (suspiciousPatterns.test(s)) cls += ' suspicious';
                return `<div class="${cls}">${escapeHtml(s)}</div>`;
            }).join('');

            if (filtered.length > 500) {
                stringsList.innerHTML += `<div class="string-line" style="color:var(--text-muted);text-align:center;padding:8px;">... ${filtered.length - 500} more strings not shown</div>`;
            }
        }

        renderList(currentStrings);

        stringsFilter.addEventListener('input', () => {
            const query = stringsFilter.value.toLowerCase();
            if (!query) {
                renderList(currentStrings);
                return;
            }
            const filtered = currentStrings.filter(s => s.toLowerCase().includes(query));
            renderList(filtered);
        });
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function resetUI() {
        uploadSection.classList.remove('hidden');
        resultsSection.classList.add('hidden');
        webhooksCard.classList.add('hidden');
        jarCard.classList.add('hidden');
        fileInput.value = '';
        stringsFilter.value = '';
        gaugeFill.style.width = '0%';
    }
})();
