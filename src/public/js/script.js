document.addEventListener('DOMContentLoaded', () => {
    // --- Algorithm Selection ---
    const algoEncrypt = document.getElementById('algo-encrypt');
    const algoSign = document.getElementById('algo-sign');
    const algoHash = document.getElementById('algo-hash');
    const algoKeyx = document.getElementById('algo-keyx');

    // ECC setup
    const ec = new elliptic.ec('p256');

    // --- Animated Data Flow Icons ---
    const animIconM = document.getElementById('anim-icon-m');
    const animIconH = document.getElementById('anim-icon-h');
    const animIconS = document.getElementById('anim-icon-s');
    
    // Helper to animate icon from one box to another
    function animateIcon(icon, fromElem, toElem, callback) {
        if (!icon || !fromElem || !toElem) return;
        // Get bounding rects relative to parent
        const parent = fromElem.offsetParent;
        const fromRect = fromElem.getBoundingClientRect();
        const toRect = toElem.getBoundingClientRect();
        const parentRect = parent.getBoundingClientRect();
        // Start at fromElem
        icon.style.left = (fromRect.left - parentRect.left - 40) + 'px';
        icon.style.top = (fromRect.top - parentRect.top + 8) + 'px';
        icon.classList.remove('hidden');
        // Animate to toElem
        setTimeout(() => {
            icon.style.left = (toRect.left - parentRect.left - 40) + 'px';
            icon.style.top = (toRect.top - parentRect.top + 8) + 'px';
        }, 10);
        // Hide after animation
        setTimeout(() => {
            icon.classList.add('hidden');
            if (callback) callback();
        }, 800);
    }
    // State variables
    let aliceKeys = {}, bobKeys = {};
    let message, hashedMessage, signature, sessionKey;
    let encryptedMessage, encryptedSessionKey;
    let currentStep = 0;
    // MITM state
    let mitmEnabled = false;
    let mitmTampered = false;

    const rsaKeySize = 2048; // For faster simulation; use 4096 for analysis

    // DOM Elements
    // MITM DOM
    const mitmCheckbox = document.getElementById('mitm-checkbox');
    const mitmAttackerView = document.getElementById('mitm-attacker-view');
    const mitmCiphertext = document.getElementById('mitm-ciphertext');
    const btnTamper = document.getElementById('btn-tamper');
    const tamperStatus = document.getElementById('tamper-status');
    const mitmEditCiphertext = document.getElementById('mitm-edit-ciphertext');
    const views = {
        sim: document.getElementById('view-sim'),
        chat: document.getElementById('view-chat'),
        perf: document.getElementById('view-perf'),
    };
    const tabs = {
        sim: document.getElementById('tab-sim'),
        chat: document.getElementById('tab-chat'),
        perf: document.getElementById('tab-perf'),
    };
    const buttons = {
        genKeys: document.getElementById('btn-gen-keys'),
        hash: document.getElementById('btn-hash'),
        sign: document.getElementById('btn-sign'),
        encrypt: document.getElementById('btn-encrypt'),
        send: document.getElementById('btn-send'),
        decryptKey: document.getElementById('btn-decrypt-key'),
        decryptMsg: document.getElementById('btn-decrypt-msg'),
        verify: document.getElementById('btn-verify'),
        reset: document.getElementById('btn-reset'),
    };
    const outputs = {
        msg: document.getElementById('out-msg'),
        hash: document.getElementById('out-hash'),
        sign: document.getElementById('out-sign'),
        c: document.getElementById('out-c'),
        ek: document.getElementById('out-ek'),
        rec_c: document.getElementById('rec-c'),
        rec_ek: document.getElementById('rec-ek'),
        dec_key: document.getElementById('out-dec-key'),
        dec_msg: document.getElementById('out-dec-msg'),
        verify: document.getElementById('out-verify'),
    };
    const steps = {
        msg: document.getElementById('step-msg'),
        hash: document.getElementById('step-hash'),
        sign: document.getElementById('step-sign'),
        encrypt: document.getElementById('step-encrypt'),
        receive: document.getElementById('step-receive'),
        decryptKey: document.getElementById('step-decrypt-key'),
        decryptMsg: document.getElementById('step-decrypt-msg'),
        verify: document.getElementById('step-verify'),
    };
    const explanationBox = document.getElementById('explanation-box');
    const messageInput = document.getElementById('message-input');
    
    // --- MITM Checkbox Logic ---
    mitmCheckbox.addEventListener('change', () => {
        mitmEnabled = mitmCheckbox.checked;
        // Hide attacker view and reset tamper state if unchecked
        if (!mitmEnabled) {
            mitmAttackerView.classList.add('hidden');
            mitmTampered = false;
            tamperStatus.textContent = '';
        }
    });

    // --- Tamper Button Logic ---
    if (btnTamper) {
        btnTamper.addEventListener('click', () => {
            if (!mitmTampered) {
                // Use user-edited ciphertext if provided, else keep original
                let newCipher = mitmEditCiphertext && mitmEditCiphertext.value.trim() ? mitmEditCiphertext.value.trim() : encryptedMessage;
                if (newCipher !== encryptedMessage) {
                    encryptedMessage = newCipher;
                    mitmTampered = true;
                    mitmCiphertext.textContent = encryptedMessage.substring(0, 30) + '...';
                    tamperStatus.textContent = 'Ciphertext tampered!';
                } else {
                    tamperStatus.textContent = 'Edit the ciphertext above to tamper!';
                }
            }
        });
    }
    Object.keys(tabs).forEach(key => {
        tabs[key].addEventListener('click', () => {
            Object.keys(views).forEach(viewKey => {
                views[viewKey].classList.toggle('hidden', viewKey !== key);
                tabs[viewKey].classList.toggle('active', viewKey === key);
            });
        });
    });

    // --- Simulation Logic ---
    const explanations = [
        `First, click <strong>Generate Keys</strong>. This creates a unique public and private RSA key pair for both the sender (Alice) and the receiver (Bob).`,
        `Now, with the message ready, click <strong>Hash Message</strong>. This uses SHA-256 to create a unique, fixed-size fingerprint (digest) of the message.`,
        `Next, click <strong>Sign Hash</strong>. The hash is encrypted with Alice's private key. This creates a digital signature, proving the message came from her.`,
        `Click <strong>Encrypt</strong>. A random, one-time AES session key is created to encrypt the message and signature. This key is then encrypted with Bob's public key.`,
        `Click <strong>Send to Bob</strong>. The encrypted message (Ciphertext) and the encrypted session key are sent across the insecure channel.`,
        `Bob has received the data. Click <strong>Decrypt Key</strong>. Bob uses his private key to decrypt the AES session key. No one else can do this.`,
        `Now, click <strong>Decrypt Msg</strong>. The decrypted session key is used to decrypt the main message content and the attached digital signature.`,
        `Finally, click <strong>Verify Signature</strong>. The decrypted message is hashed again. Alice's public key is used to decrypt the signature, revealing the original hash. If they match, the message is authentic.`,
        `<strong>Success!</strong> The signature is valid. The message has been securely transmitted with confidentiality, integrity, and authenticity.`
    ];

    const updateUI = () => {
        // Update explanation
        explanationBox.querySelector('p').innerHTML = explanations[currentStep];

        // Update button states
        Object.values(buttons).forEach(btn => btn.disabled = true);
        buttons.reset.disabled = false;
        
        if (currentStep === 0) buttons.genKeys.disabled = false;
        else if (currentStep === 1) buttons.hash.disabled = false;
        else if (currentStep === 2) buttons.sign.disabled = false;
        else if (currentStep === 3) buttons.encrypt.disabled = false;
        else if (currentStep === 4) buttons.send.disabled = false;
        else if (currentStep === 5) buttons.decryptKey.disabled = false;
        else if (currentStep === 6) buttons.decryptMsg.disabled = false;
        else if (currentStep === 7) buttons.verify.disabled = false;

        // Update active step highlight
        Object.values(steps).forEach(s => s.classList.remove('active'));
        if (currentStep === 1) steps.msg.classList.add('active');
        if (currentStep === 2) steps.hash.classList.add('active');
        if (currentStep === 3) steps.sign.classList.add('active');
        if (currentStep === 4) steps.encrypt.classList.add('active');
        if (currentStep === 5) steps.receive.classList.add('active');
        if (currentStep === 6) steps.decryptKey.classList.add('active');
        if (currentStep === 7) steps.decryptMsg.classList.add('active');
        if (currentStep === 8) steps.verify.classList.add('active');

        // Update algorithm flowchart
        renderAlgoFlowchart();
    };

    // --- Algorithm Flowchart Logic ---
    const algoFlowSteps = {
        aes: [
            { label: 'Message', desc: 'Input message (M)' },
            { label: 'Session Key', desc: 'Generate random AES key' },
            { label: 'Encrypt', desc: 'Encrypt message with AES key' },
            { label: 'Send', desc: 'Send ciphertext and key (encrypted)' },
            { label: 'Decrypt', desc: 'Decrypt ciphertext with AES key' }
        ],
        caesar: [
            { label: 'Message', desc: 'Input message (M)' },
            { label: 'Shift', desc: 'Choose shift value (e.g., 3)' },
            { label: 'Encrypt', desc: 'Shift each letter by value' },
            { label: 'Send', desc: 'Send ciphertext' },
            { label: 'Decrypt', desc: 'Reverse shift to get message' }
        ],
        shift: [
            { label: 'Message', desc: 'Input message (M)' },
            { label: 'Shift', desc: 'Choose shift value (e.g., 5)' },
            { label: 'Encrypt', desc: 'Shift all chars by value' },
            { label: 'Send', desc: 'Send ciphertext' },
            { label: 'Decrypt', desc: 'Reverse shift to get message' }
        ],
        transposition: [
            { label: 'Message', desc: 'Input message (M)' },
            { label: 'Arrange', desc: 'Write in columns (e.g., 5 cols)' },
            { label: 'Read', desc: 'Read column-wise to get ciphertext' },
            { label: 'Send', desc: 'Send ciphertext' },
            { label: 'Decrypt', desc: 'Reverse columns to get message' }
        ],
        affine: [
            { label: 'Message', desc: 'Input message (M)' },
            { label: 'Keys', desc: 'Choose a, b (e.g., a=5, b=8)' },
            { label: 'Encrypt', desc: 'Apply affine formula to each letter' },
            { label: 'Send', desc: 'Send ciphertext' },
            { label: 'Decrypt', desc: 'Apply inverse affine to get message' }
        ],
        rsa: [
            { label: 'Message', desc: 'Input message (M)' },
            { label: 'Keygen', desc: 'Generate RSA key pair' },
            { label: 'Encrypt', desc: 'Encrypt with public key' },
            { label: 'Send', desc: 'Send ciphertext' },
            { label: 'Decrypt', desc: 'Decrypt with private key' }
        ],
        ecc: [
            { label: 'Message', desc: 'Input message (M)' },
            { label: 'Keygen', desc: 'Generate ECC key pair' },
            { label: 'ECDH', desc: 'Derive shared secret' },
            { label: 'Encrypt', desc: 'Encrypt with shared secret' },
            { label: 'Send', desc: 'Send ciphertext' },
            { label: 'Decrypt', desc: 'Decrypt with shared secret' }
        ]
    };

    function renderAlgoFlowchart() {
        const flowDiv = document.getElementById('algo-flowchart');
        if (!flowDiv) return;
        const selected = algoEncrypt.value;
        const steps = algoFlowSteps[selected] || [];
        // Map simulation step to flowchart step (approximate)
        let flowStep = 0;
        if (currentStep === 0) flowStep = 0;
        else if (currentStep === 1) flowStep = 0;
        else if (currentStep === 2) flowStep = 1;
        else if (currentStep === 3) flowStep = 2;
        else if (currentStep === 4) flowStep = 3;
        else if (currentStep === 5) flowStep = 3;
        else if (currentStep === 6) flowStep = 4;
        else if (currentStep >= 7) flowStep = steps.length - 1;

        flowDiv.innerHTML = '';
        if (steps.length === 0) return;
        // Render steps as boxes with arrows
        for (let i = 0; i < steps.length; i++) {
            const step = steps[i];
            const box = document.createElement('div');
            box.className = 'flex flex-col items-center mb-2';
            box.innerHTML = `<div class="px-4 py-2 rounded-lg shadow text-center ${i === flowStep ? 'bg-indigo-500 text-white font-bold scale-105' : 'bg-gray-700 text-gray-200'} transition-all duration-200">${step.label}</div><div class="text-xs text-gray-400 mt-1">${step.desc}</div>`;
            flowDiv.appendChild(box);
            if (i < steps.length - 1) {
                const arrow = document.createElement('div');
                arrow.innerHTML = '<svg height="24" width="24"><path d="M12 0 v20 M12 20 l-5 -5 M12 20 l5 -5" stroke="#888" stroke-width="2" fill="none"/></svg>';
                arrow.className = 'mb-2';
                flowDiv.appendChild(arrow);
            }
        }
    }

    // Update flowchart on algorithm change
    algoEncrypt.addEventListener('change', renderAlgoFlowchart);
    
    const truncate = (str) => str.length > 30 ? str.substring(0, 30) + '...' : str;

    buttons.genKeys.addEventListener('click', () => {
        const encAlgo = algoEncrypt.value;
        const signAlgo = algoSign.value;
        const keyxAlgo = algoKeyx.value;
        explanationBox.querySelector('p').textContent = `Generating keys for selected algorithms...`;
        setTimeout(() => {
            // Always generate both RSA and ECC key pairs for both Alice and Bob
            // RSA
            const aliceCrypt = new JSEncrypt({ default_key_size: rsaKeySize });
            aliceKeys.rsa = { private: aliceCrypt.getPrivateKey(), public: aliceCrypt.getPublicKey() };
            const bobCrypt = new JSEncrypt({ default_key_size: rsaKeySize });
            bobKeys.rsa = { private: bobCrypt.getPrivateKey(), public: bobCrypt.getPublicKey() };
            // ECC
            const aliceEc = ec.genKeyPair();
            const bobEc = ec.genKeyPair();
            aliceKeys.ecc = { private: aliceEc.getPrivate('hex'), public: aliceEc.getPublic('hex') };
            bobKeys.ecc = { private: bobEc.getPrivate('hex'), public: bobEc.getPublic('hex') };
            alert('Keys Generated!\n\nAlice RSA Public Key:\n' + aliceKeys.rsa.public.substring(0, 100) + '\nAlice ECC Public Key:\n' + aliceKeys.ecc.public.substring(0, 100) + '\n\nBob RSA Public Key:\n' + bobKeys.rsa.public.substring(0, 100) + '\nBob ECC Public Key:\n' + bobKeys.ecc.public.substring(0, 100));
            currentStep = 1;
            updateUI();
        }, 100);
    });

    buttons.hash.addEventListener('click', () => {
        message = messageInput.value;
        // Hash selection
        if (algoHash.value === 'sha256') {
            hashedMessage = CryptoJS.SHA256(message).toString();
        } else if (algoHash.value === 'sha512') {
            hashedMessage = CryptoJS.SHA512(message).toString();
        } else if (algoHash.value === 'sha3') {
            hashedMessage = CryptoJS.SHA3(message).toString();
        }
        outputs.msg.textContent = truncate(message);
        outputs.hash.textContent = truncate(hashedMessage);
        animateIcon(
            animIconM,
            steps.msg,
            steps.hash,
            () => {
                currentStep = 2;
                updateUI();
            }
        );
    });

    buttons.sign.addEventListener('click', () => {
        // Signature selection
        if (algoSign.value === 'rsa') {
            const sign = new JSEncrypt();
            sign.setPrivateKey(aliceKeys.rsa.private);
            signature = sign.sign(hashedMessage, CryptoJS.SHA256, algoHash.value);
        } else if (algoSign.value === 'ecc') {
            const key = ec.keyFromPrivate(aliceKeys.ecc.private, 'hex');
            const sigObj = key.sign(hashedMessage);
            signature = sigObj.toDER('hex');
        }
        outputs.sign.textContent = truncate(signature);
        animateIcon(
            animIconH,
            steps.hash,
            steps.sign,
            () => {
                currentStep = 3;
                updateUI();
            }
        );
    });

    buttons.encrypt.addEventListener('click', () => {
        // Key Exchange selection
        if (algoKeyx.value === 'ecc') {
            // ECDH: derive shared secret
            const aliceKey = ec.keyFromPrivate(aliceKeys.ecc.private, 'hex');
            const bobKey = ec.keyFromPrivate(bobKeys.ecc.private, 'hex');
            sessionKey = aliceKey.derive(bobKey.getPublic()).toString(16).substring(0, 32);
        } else {
            sessionKey = CryptoJS.lib.WordArray.random(16).toString(); // 128-bit key
        }
        const dataToEncrypt = JSON.stringify({ msg: message, sig: signature });
        // Encryption selection
        if (algoEncrypt.value === 'aes') {
            encryptedMessage = CryptoJS.AES.encrypt(dataToEncrypt, sessionKey).toString();
            encryptedSessionKey = sessionKey; // For demo, not encrypted
        } else if (algoEncrypt.value === 'caesar') {
            encryptedMessage = caesarEncrypt(dataToEncrypt, 3); // shift 3
            encryptedSessionKey = sessionKey;
        } else if (algoEncrypt.value === 'shift') {
            encryptedMessage = shiftEncrypt(dataToEncrypt, 5); // shift 5
            encryptedSessionKey = sessionKey;
        } else if (algoEncrypt.value === 'transposition') {
            encryptedMessage = transpositionEncrypt(dataToEncrypt);
            encryptedSessionKey = sessionKey;
        } else if (algoEncrypt.value === 'affine') {
            encryptedMessage = affineEncrypt(dataToEncrypt, 5, 8); // a=5, b=8
            encryptedSessionKey = sessionKey;
        } else if (algoEncrypt.value === 'rsa') {
            encryptedMessage = CryptoJS.AES.encrypt(dataToEncrypt, sessionKey).toString();
            const encrypt = new JSEncrypt();
            encrypt.setPublicKey(bobKeys.rsa.public);
            encryptedSessionKey = encrypt.encrypt(sessionKey);
        } else if (algoEncrypt.value === 'ecc') {
            encryptedMessage = CryptoJS.AES.encrypt(dataToEncrypt, sessionKey).toString();
            encryptedSessionKey = sessionKey; // For demo, not encrypted
        }
        outputs.c.textContent = truncate(encryptedMessage);
        outputs.ek.textContent = truncate(encryptedSessionKey);
        currentStep = 4;
        updateUI();
    });

    buttons.send.addEventListener('click', () => {
        if (mitmEnabled) {
            // Show attacker view and allow tampering
            mitmAttackerView.classList.remove('hidden');
            mitmCiphertext.textContent = truncate(encryptedMessage);
            if (mitmEditCiphertext) mitmEditCiphertext.value = encryptedMessage;
            tamperStatus.textContent = '';
            // Wait for tampering before sending to Bob
            outputs.rec_c.textContent = '...';
            outputs.rec_ek.textContent = '...';
            // After tampering, user must click send again to deliver to Bob
            buttons.send.textContent = mitmTampered ? 'Deliver to Bob' : 'Send to Bob';
            if (mitmTampered) {
                outputs.rec_c.textContent = truncate(encryptedMessage);
                outputs.rec_ek.textContent = truncate(encryptedSessionKey);
                currentStep = 5;
                updateUI();
                // Hide attacker view after delivery
                setTimeout(() => {
                    mitmAttackerView.classList.add('hidden');
                    buttons.send.textContent = 'Send to Bob';
                }, 1000);
            }
            return;
        } else {
            outputs.rec_c.textContent = truncate(encryptedMessage);
            outputs.rec_ek.textContent = truncate(encryptedSessionKey);
            currentStep = 5;
            updateUI();
        }
    });

    buttons.decryptKey.addEventListener('click', () => {
        let decrypted = null;
        if (algoEncrypt.value === 'rsa') {
            const decrypt = new JSEncrypt();
            decrypt.setPrivateKey(bobKeys.rsa.private);
            decrypted = decrypt.decrypt(encryptedSessionKey);
        } else if (algoEncrypt.value === 'aes' || algoEncrypt.value === 'ecc' || algoEncrypt.value === 'caesar' || algoEncrypt.value === 'shift' || algoEncrypt.value === 'transposition' || algoEncrypt.value === 'affine') {
            decrypted = encryptedSessionKey;
        }
        if (decrypted === sessionKey) {
            outputs.dec_key.textContent = truncate(decrypted);
            currentStep = 6;
            updateUI();
        } else {
            alert('Error: Failed to decrypt session key!');
        }
    });

    buttons.decryptMsg.addEventListener('click', () => {
        let decryptedData;
        try {
            if (algoEncrypt.value === 'caesar') {
                decryptedData = JSON.parse(caesarDecrypt(encryptedMessage, 3));
            } else if (algoEncrypt.value === 'shift') {
                decryptedData = JSON.parse(shiftDecrypt(encryptedMessage, 5));
            } else if (algoEncrypt.value === 'transposition') {
                decryptedData = JSON.parse(transpositionDecrypt(encryptedMessage));
            } else if (algoEncrypt.value === 'affine') {
                decryptedData = JSON.parse(affineDecrypt(encryptedMessage, 5, 8));
            } else {
                let bytes = CryptoJS.AES.decrypt(encryptedMessage, sessionKey);
                decryptedData = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
            }
        } catch (e) {
            decryptedData = { msg: '???', sig: '' };
        }
        outputs.dec_msg.textContent = truncate(decryptedData.msg);
        outputs.dec_msg.dataset.fullmsg = decryptedData.msg;
        outputs.dec_msg.dataset.sig = decryptedData.sig;
        currentStep = 7;
        updateUI();
    });

// --- Basic Cipher Implementations ---
function caesarEncrypt(str, shift) {
    return str.replace(/[a-z]/gi, c => {
        const base = c >= 'a' && c <= 'z' ? 97 : 65;
        return String.fromCharCode(((c.charCodeAt(0) - base + shift) % 26) + base);
    });
}

function caesarDecrypt(str, shift) {
    return str.replace(/[a-z]/gi, c => {
        const base = c >= 'a' && c <= 'z' ? 97 : 65;
        return String.fromCharCode(((c.charCodeAt(0) - base - shift + 26) % 26) + base);
    });
}

function shiftEncrypt(str, shift) {
    return str.split('').map(c => String.fromCharCode((c.charCodeAt(0) + shift) % 256)).join('');
}

function shiftDecrypt(str, shift) {
    return str.split('').map(c => String.fromCharCode((c.charCodeAt(0) - shift + 256) % 256)).join('');
}

function transpositionEncrypt(str) {
    // Simple columnar transposition with 5 columns
    const numCols = 5;
    let arr = Array.from({length: numCols}, () => '');
    for (let i = 0; i < str.length; i++) {
        arr[i % numCols] += str[i];
    }
    return arr.join('');
}

function transpositionDecrypt(str) {
    // Properly reverse the columnar transposition with 5 columns
    const numCols = 5;
    const numRows = Math.ceil(str.length / numCols);
    let arr = Array(numRows).fill('');
    let shortCols = numCols - (str.length % numCols);
    if (shortCols === numCols) shortCols = 0;
    let k = 0;
    for (let col = 0; col < numCols; col++) {
        let thisColLen = numRows - (col >= numCols - shortCols ? 1 : 0);
        for (let row = 0; row < thisColLen; row++) {
            arr[row] += str[k++];
        }
    }
    return arr.join('');
}

function affineEncrypt(str, a, b) {
    // Only for letters
    return str.replace(/[a-z]/gi, c => {
        const base = c >= 'a' && c <= 'z' ? 97 : 65;
        return String.fromCharCode(((a * (c.charCodeAt(0) - base) + b) % 26) + base);
    });
}

function modInverse(a, m) {
    // Extended Euclidean Algorithm
    a = ((a % m) + m) % m;
    for (let x = 1; x < m; x++) {
        if ((a * x) % m === 1) return x;
    }
    return 1;
}

function affineDecrypt(str, a, b) {
    const a_inv = modInverse(a, 26);
    return str.replace(/[a-z]/gi, c => {
        const base = c >= 'a' && c <= 'z' ? 97 : 65;
        return String.fromCharCode(((a_inv * ((c.charCodeAt(0) - base - b + 26)) % 26) + base));
    });
}

    buttons.verify.addEventListener('click', () => {
        const receivedMsg = outputs.dec_msg.dataset.fullmsg;
        const receivedSig = outputs.dec_msg.dataset.sig;
        let newHash = null;
        if (algoHash.value === 'sha256') {
            newHash = CryptoJS.SHA256(receivedMsg).toString();
        } else if (algoHash.value === 'sha512') {
            newHash = CryptoJS.SHA512(receivedMsg).toString();
        }
        let isValid = false;
        if (algoSign.value === 'rsa') {
            const verify = new JSEncrypt();
            verify.setPublicKey(aliceKeys.rsa.public);
            try {
                isValid = verify.verify(newHash, receivedSig, CryptoJS.SHA256);
            } catch (e) { isValid = false; }
        } else if (algoSign.value === 'ecc') {
            try {
                const key = ec.keyFromPublic(aliceKeys.ecc.public, 'hex');
                isValid = key.verify(newHash, receivedSig);
            } catch (e) { isValid = false; }
        }
        if (mitmEnabled && mitmTampered) {
            outputs.verify.textContent = "INVALID SIGNATURE";
            outputs.verify.className = "font-bold text-3xl text-red-600 animate-pulse";
        } else if (isValid) {
            outputs.verify.textContent = "VALID";
            outputs.verify.className = "font-bold text-2xl text-green-400";
        } else {
            outputs.verify.textContent = "INVALID";
            outputs.verify.className = "font-bold text-2xl text-red-500";
        }
        currentStep = 8;
        updateUI();
    });
    
    buttons.reset.addEventListener('click', () => {
        location.reload();
    });

    // --- Performance Logic ---
    const perfBtn = document.getElementById('run-perf-test');
    const perfTable = document.getElementById('perf-results');
    const perfSpinner = document.getElementById('perf-spinner');
    const perfStatus = document.getElementById('perf-status');
    const perfChartCanvas = document.getElementById('perf-chart');
    const perfThroughputCanvas = document.getElementById('perf-throughput-chart');
    const perfKeySizeCanvas = document.getElementById('perf-keysize-chart');
    const perfAnalysis = document.getElementById('perf-analysis');
    let perfChart;
    let perfThroughputChart;
    let perfKeySizeChart;
    let benchmarkResults = [];

    async function runBenchmark() {
        perfSpinner.classList.remove('hidden');
        perfTable.innerHTML = '';
        benchmarkResults = []; // Clear previous results
        if (perfChart) perfChart.destroy(); // Clear previous chart
        if (perfThroughputChart) perfThroughputChart.destroy();
        perfStatus.textContent = 'Running tests... please wait.';

        const testMessage1KB = 'a'.repeat(1024);
        const testMessage1MB = 'a'.repeat(1024 * 1024);

        // RSA-2048 / AES-128 / SHA-256 (Baseline)
        await runTestSet('RSA-2048 / AES-128 / SHA-256', 2048, CryptoJS.lib.WordArray.random(16), CryptoJS.SHA256, 'sha256', testMessage1KB, '1KB');
        await runTestSet('RSA-2048 / AES-128 / SHA-256', 2048, CryptoJS.lib.WordArray.random(16), CryptoJS.SHA256, 'sha256', testMessage1MB, '1MB');

        // RSA-4096 / AES-256 / SHA-512 (Higher Security)
        await runTestSet('RSA-4096 / AES-256 / SHA-512', 4096, CryptoJS.lib.WordArray.random(32), CryptoJS.SHA512, 'sha512', testMessage1KB, '1KB');
        await runTestSet('RSA-4096 / AES-256 / SHA-512', 4096, CryptoJS.lib.WordArray.random(32), CryptoJS.SHA512, 'sha512', testMessage1MB, '1MB');

        // --- Basic Cipher Benchmarks ---
        await runBasicCipherBenchmarks('1KB', testMessage1KB);
        await runBasicCipherBenchmarks('1MB', testMessage1MB);

        perfSpinner.classList.add('hidden');
        perfStatus.textContent = 'Benchmark complete.';
        renderPerfChart();
        renderThroughputChart();
        renderKeySizeChart();
        updatePerfAnalysis();

        // --- Key Size vs. Performance Chart ---
        function renderKeySizeChart() {
            // Find relevant results for RSA-2048 and RSA-4096
            const keySizes = [2048, 4096];
            const ops = ['Key Generation', 'Signing'];
            const labels = ['RSA-2048', 'RSA-4096'];
            // For each key size, get keygen and sign times (1KB row is fine)
            const keygenTimes = keySizes.map(size => {
                const row = benchmarkResults.find(r => r.op === `RSA-${size} Gen`);
                return row ? row.time : 0;
            });
            const signTimes = keySizes.map((size, i) => {
                // Find the sign op for this key size (1KB row is fine)
                const setName = size === 2048 ? 'RSA-2048 / AES-128 / SHA-256' : 'RSA-4096 / AES-256 / SHA-512';
                const row = benchmarkResults.find(r => r.set === setName && r.op === 'RSA Sign' && r.size === '1KB');
                return row ? row.time : 0;
            });
            const ctx = perfKeySizeCanvas.getContext('2d');
            if (perfKeySizeChart) perfKeySizeChart.destroy();
            perfKeySizeChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'Key Generation (ms)',
                            data: keygenTimes,
                            backgroundColor: 'rgba(153, 102, 255, 0.7)',
                            borderColor: 'rgba(153, 102, 255, 1)',
                            borderWidth: 1
                        },
                        {
                            label: 'Signing (ms)',
                            data: signTimes,
                            backgroundColor: 'rgba(255, 159, 64, 0.7)',
                            borderColor: 'rgba(255, 159, 64, 1)',
                            borderWidth: 1
                        }
                    ]
                },
                options: {
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Time (ms)'
                            }
                        }
                    },
                    plugins: {
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    return `${context.dataset.label}: ${context.raw.toFixed(2)} ms`;
                                }
                            }
                        }
                    }
                }
            });
        }
    }

    // Add basic ciphers to benchmark
    async function runBasicCipherBenchmarks(sizeLabel, message) {
        // Caesar
        let start = performance.now();
        let enc = caesarEncrypt(message, 3);
        let dec = caesarDecrypt(enc, 3);
        let end = performance.now();
        addPerfRow('Basic Ciphers', 'Caesar Encrypt+Decrypt', sizeLabel, (end - start).toFixed(2));

        // Shift
        start = performance.now();
        enc = shiftEncrypt(message, 5);
        dec = shiftDecrypt(enc, 5);
        end = performance.now();
        addPerfRow('Basic Ciphers', 'Shift Encrypt+Decrypt', sizeLabel, (end - start).toFixed(2));

        // Transposition
        start = performance.now();
        enc = transpositionEncrypt(message);
        dec = transpositionDecrypt(enc);
        end = performance.now();
        addPerfRow('Basic Ciphers', 'Transposition Encrypt+Decrypt', sizeLabel, (end - start).toFixed(2));

        // Affine
        start = performance.now();
        enc = affineEncrypt(message, 5, 8);
        dec = affineDecrypt(enc, 5, 8);
        end = performance.now();
        addPerfRow('Basic Ciphers', 'Affine Encrypt+Decrypt', sizeLabel, (end - start).toFixed(2));
    }
    // --- Throughput Chart ---
    function renderThroughputChart() {
        // Only use 1MB results for throughput
        const throughputOps = [
            { label: 'AES-128 Encrypt', set: 'RSA-2048 / AES-128 / SHA-256', op: 'AES-128 Encrypt', hash: false },
            { label: 'AES-256 Encrypt', set: 'RSA-4096 / AES-256 / SHA-512', op: 'AES-256 Encrypt', hash: false },
            { label: 'SHA-256 Hash', set: 'RSA-2048 / AES-128 / SHA-256', op: 'SHA256 Hash', hash: true },
            { label: 'SHA-512 Hash', set: 'RSA-4096 / AES-256 / SHA-512', op: 'SHA512 Hash', hash: true }
        ];
        const labels = throughputOps.map(x => x.label);
        const data = throughputOps.map(x => {
            // Find the 1MB result for this op
            const result = benchmarkResults.find(r => r.set === x.set && r.op.startsWith(x.op) && r.size === '1MB');
            if (!result || !result.time) return 0;
            // MB/s = 1MB / (time in seconds)
            return 1 / (result.time / 1000);
        });
        const ctx = perfThroughputCanvas.getContext('2d');
        perfThroughputChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Throughput (MB/s)',
                    data: data,
                    backgroundColor: [
                        'rgba(54, 162, 235, 0.7)',
                        'rgba(255, 99, 132, 0.7)',
                        'rgba(255, 206, 86, 0.7)',
                        'rgba(75, 192, 192, 0.7)'
                    ],
                    borderColor: [
                        'rgba(54, 162, 235, 1)',
                        'rgba(255, 99, 132, 1)',
                        'rgba(255, 206, 86, 1)',
                        'rgba(75, 192, 192, 1)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Throughput (MB/s)'
                        }
                    }
                },
                plugins: {
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return `${context.dataset.label}: ${context.raw.toFixed(2)} MB/s`;
                            }
                        }
                    }
                }
            }
        });
    }

    async function runTestSet(setName, keySize, aesKey, hashFn, hashName, message, msgSizeLabel) {
        return new Promise(resolve => {
            setTimeout(() => {
                let start, end;
                
                start = performance.now();
                const crypt = new JSEncrypt({ default_key_size: keySize });
                const pubKey = crypt.getPublicKey();
                const privKey = crypt.getPrivateKey();
                end = performance.now();
                addPerfRow(setName, `RSA-${keySize} Gen`, '-', (end - start).toFixed(2));

                start = performance.now();
                const hash = hashFn(message).toString();
                end = performance.now();
                addPerfRow(setName, `${hashName.toUpperCase()} Hash`, msgSizeLabel, (end - start).toFixed(2));

                const signCrypt = new JSEncrypt();
                signCrypt.setPrivateKey(privKey);
                start = performance.now();
                signCrypt.sign(hash, hashFn, hashName);
                end = performance.now();
                addPerfRow(setName, 'RSA Sign', msgSizeLabel, (end - start).toFixed(2));

                const sKey = aesKey.toString();
                start = performance.now();
                CryptoJS.AES.encrypt(message, sKey).toString();
                end = performance.now();
                addPerfRow(setName, `AES-${aesKey.sigBytes * 8} Encrypt`, msgSizeLabel, (end - start).toFixed(2));

                const encCrypt = new JSEncrypt();
                encCrypt.setPublicKey(pubKey);
                start = performance.now();
                encCrypt.encrypt(sKey);
                end = performance.now();
                addPerfRow(setName, 'RSA Encrypt Key', '-', (end - start).toFixed(2));
                
                resolve();
            }, 50);
        });
    }

    function addPerfRow(set, op, size, time) {
        benchmarkResults.push({ set, op, size, time: parseFloat(time) });
        const row = perfTable.insertRow();
        row.innerHTML = `
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-300">${set}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-300">${op}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-300">${size}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm font-mono text-cyan-400">${time}</td>
        `;
    }

    perfBtn.addEventListener('click', runBenchmark);

    function renderPerfChart() {
        const datasets = {};
        const labels = [...new Set(benchmarkResults.map(r => `${r.op} (${r.size})`))];

        benchmarkResults.forEach(result => {
            if (!datasets[result.set]) {
                datasets[result.set] = {
                    label: result.set,
                    data: [],
                    backgroundColor: `rgba(${Math.random() * 255}, ${Math.random() * 255}, ${Math.random() * 255}, 0.6)`,
                    borderColor: `rgba(${Math.random() * 255}, ${Math.random() * 255}, ${Math.random() * 255}, 1)`,
                    borderWidth: 1
                };
            }
        });

        for (const set in datasets) {
            datasets[set].data = labels.map(label => {
                const match = benchmarkResults.find(r => r.set === set && `${r.op} (${r.size})` === label);
                return match ? match.time : 0;
            });
        }

        const ctx = perfChartCanvas.getContext('2d');
        perfChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: Object.values(datasets)
            },
            options: {
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Time (ms)'
                        }
                    }
                },
                plugins: {
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return `${context.dataset.label}: ${context.raw.toFixed(2)} ms`;
                            }
                        }
                    }
                }
            }
        });
    }

    function updatePerfAnalysis() {
        if (benchmarkResults.length === 0) return;

        const rsa4096Gen = benchmarkResults.find(r => r.op.includes('RSA-4096 Gen'))?.time || 0;
        const rsa2048Gen = benchmarkResults.find(r => r.op.includes('RSA-2048 Gen'))?.time || 0;
        const rsaGenFactor = (rsa4096Gen / rsa2048Gen).toFixed(1);

        const sha512_1MB = benchmarkResults.find(r => r.op.includes('SHA512') && r.size === '1MB')?.time || 0;
        const sha256_1MB = benchmarkResults.find(r => r.op.includes('SHA256') && r.size === '1MB')?.time || 0;
        const hashFactor = (sha512_1MB / sha256_1MB).toFixed(1);

        perfAnalysis.innerHTML = `
            <p class="mb-2"><strong>Key Generation:</strong> RSA-4096 key generation is approximately <strong>${rsaGenFactor}x slower</strong> than RSA-2048, highlighting the significant computational cost of stronger asymmetric keys.</p>
            <p class="mb-2"><strong>Hashing:</strong> For a 1MB message, SHA-512 is about <strong>${hashFactor}x slower</strong> than SHA-256. Hashing is generally very fast, but the choice of algorithm still impacts performance on larger messages.</p>
            <p><strong>Conclusion:</strong> There is a clear trade-off between security and performance. Stronger algorithms like RSA-4096 and SHA-512 provide higher security guarantees but come with a measurable performance cost, especially in key generation and signing operations.</p>
        `;
    }
    
    // --- Live Chat Logic ---
    const socket = io({
        autoConnect: false, // Prevent auto-connect
        reconnectionAttempts: 3,
        reconnectionDelay: 1000
    });
    
    // Chat state
    let chatKeys = null;
    let myUsername = null;
    let myUserId = null; // Persistent user ID
    let otherUsers = {}; // Store public keys of other users
    let selectedUser = null;
    let chatMode = 'group'; // 'group' or 'private'
    let chatInitialized = false;
    // Static group key for demo (should be securely exchanged in production)
    const groupKey = 'demo-static-group-key-123';

    // Generate or retrieve persistent userId
    function getOrCreateUserId() {
        let id = localStorage.getItem('userId');
        if (!id) {
            id = 'user-' + Math.random().toString(36).substr(2, 9) + '-' + Date.now();
            localStorage.setItem('userId', id);
        }
        return id;
    }
    myUserId = getOrCreateUserId();

    // UI Elements
    const groupChatWindow = document.getElementById('group-chat-window');
    const privateChatWindow = document.getElementById('private-chat-window');
    const chatInput = document.querySelector('#view-chat input[type="text"]');
    const chatSendButton = document.querySelector('#view-chat button');
    const userList = document.getElementById('user-list');
    const chatModeGroupBtn = document.getElementById('chat-mode-group');
    const chatModePrivateBtn = document.getElementById('chat-mode-private');

    // Store message details for inspection
    const messageStore = {};

    // Initialize chat when the chat tab is clicked
    if (tabs.chat) {
        tabs.chat.addEventListener('click', initializeChat);
    }

    // Chat initialization
    function initializeChat() {
        if (chatInitialized) return;
        
        // Get username if not set
        if (!myUsername) {
            const username = prompt("Please enter your name for the chat:");
            if (!username) {
                addNotification('Username is required to join the chat.');
                return;
            }
            myUsername = username.trim();
        }

        // Already have keys, just connect
        if (chatKeys) {
            connectToChat();
            return;
        }
        
        // Generate new keys
        chatInitialized = true;
        addNotification('Generating encryption keys... (This may take a moment)');
        
        // Generate RSA key pair for chat
        const crypt = new JSEncrypt({default_key_size: 1024});
        
        // Use setTimeout to prevent UI freeze during key generation
        setTimeout(() => {
            try {
                chatKeys = {
                    private: crypt.getPrivateKey(),
                    public: crypt.getPublicKey(),
                };
                connectToChat();
            } catch (error) {
                console.error('Error generating keys:', error);
                addNotification('Error generating encryption keys. Please refresh and try again.');
                chatInitialized = false;
            }
        }, 50);
    }

    // Connect to chat server with current credentials
    function connectToChat() {
        try {
            if (!socket.connected) {
                socket.connect();
            }
            socket.emit('join', {
                username: myUsername,
                publicKey: chatKeys.public,
                userId: myUserId
            });
            addNotification('Successfully joined the chat!');
        } catch (error) {
            console.error('Error connecting to chat:', error);
            addNotification('Error connecting to chat server. Please try again.');
        }
    }

const showInspectModal = (messageData) => {
    const modal = document.getElementById('inspect-modal');
    document.getElementById('inspect-original').textContent = messageData.message;
    document.getElementById('inspect-hash').textContent = messageData.hash || 'N/A';
    document.getElementById('inspect-encrypted').textContent = messageData.encryptedMessage || 'N/A';
    document.getElementById('inspect-signature').textContent = messageData.signature || 'N/A';
    document.getElementById('inspect-session-key').textContent = messageData.encryptedKey || 'N/A (Group messages use the same key)';
    modal.classList.remove('hidden');
    
    // Close modal when clicking the close button or outside the modal
        const closeInspect = () => {
            modal.classList.add('hidden');
            document.removeEventListener('click', handleOutsideClick);
        };
        
        const handleOutsideClick = (e) => {
            if (e.target === modal) {
                closeInspect();
            }
        };
        
        document.getElementById('close-inspect').onclick = closeInspect;
        document.addEventListener('click', handleOutsideClick);
    };

    const addChatMessage = (message, user, isYou = false, targetWindow, messageData = {}) => {
        const chatWindow = targetWindow === 'private' ? privateChatWindow : groupChatWindow;
        const messageContainer = document.createElement('div');
        messageContainer.classList.add('message-container', 'flex', 'flex-col', 'mb-2');
        // Use max-w-md for group chat messages to avoid full width
        messageContainer.classList.add('max-w-md');
        if (isYou) {
            messageContainer.classList.add('self-end', 'items-end');
        } else {
            messageContainer.classList.add('self-start', 'items-start');
        }

        const messageElement = document.createElement('div');
        messageElement.classList.add('p-3', 'rounded-lg', 'break-words', 'relative');
        if (isYou) {
            messageElement.classList.add('bg-indigo-700');
        } else {
            messageElement.classList.add('bg-gray-700');
        }

        // Sanitize message content to prevent XSS
        const sanitizedMessage = message.replace(/</g, "&lt;").replace(/>/g, "&gt;");

        // Latency display
        let latencyHtml = '';
        if (!isYou && messageData && messageData.timestamp && messageData.sentTimestamp) {
            // Calculate latency in ms
            const sent = new Date(messageData.sentTimestamp).getTime();
            const received = new Date(messageData.timestamp).getTime();
            if (!isNaN(sent) && !isNaN(received)) {
                const latency = received - sent;
                latencyHtml = `<span class=\"text-xs text-cyan-400 ml-2\">(${latency}ms)</span>`;
            }
        }

        messageElement.innerHTML = `
            <p class=\"font-bold\">${isYou ? myUsername : user}</p>
            <p>${sanitizedMessage}</p>
            <p class=\"text-xs text-gray-400 text-right\">${new Date().toLocaleTimeString()}${latencyHtml}</p>
            <span class=\"message-inspect\">🔍</span>
        `;

        // Add click handler to the inspect button
        const inspectBtn = messageElement.querySelector('.message-inspect');
        if (inspectBtn) {
            inspectBtn.onclick = (e) => {
                e.stopPropagation();
                showInspectModal(messageData);
            };
        }
        messageContainer.appendChild(messageElement);
        chatWindow.appendChild(messageContainer);
        chatWindow.scrollTop = chatWindow.scrollHeight;
    };

    const addNotification = (message, targetWindow) => {
        let chatWindow;
        if (targetWindow === 'private') {
            chatWindow = privateChatWindow;
        } else if (targetWindow === 'group') {
            chatWindow = groupChatWindow;
        } else {
            // fallback: if 'system' or anything else, use group chat window
            chatWindow = groupChatWindow;
        }
        if (!chatWindow || typeof chatWindow.appendChild !== 'function') return;
        const notificationElement = document.createElement('div');
        notificationElement.classList.add('text-center', 'text-gray-500', 'text-sm', 'my-2');
        notificationElement.textContent = message;
        chatWindow.appendChild(notificationElement);
        chatWindow.scrollTop = chatWindow.scrollHeight;
    };

    // --- Socket Event Handlers ---
    function setupSocketListeners() {
        socket.on('connect', () => {
            console.log('Connected to server');
            if (chatKeys && myUsername) {
                // Re-join the chat if we were connected before
                socket.emit('join', { 
                    username: myUsername, 
                    publicKey: chatKeys.public 
                });
            }
        });

        socket.on('disconnect', (reason) => {
            console.log('Disconnected from server:', reason);
            if (reason === 'io server disconnect' || reason === 'io client disconnect') {
                // Manual disconnection, don't show reconnection message
                return;
            }
            addNotification('Disconnected from server. Attempting to reconnect...');
        });

        socket.on('connect_error', (error) => {
            console.error('Connection error:', error);
            addNotification('Connection error. Please check your internet connection.');
        });

        socket.on('user joined', (userData) => {
            console.log('User joined:', userData);
            // Don't add yourself to otherUsers
            if (userData.userId && userData.userId === myUserId) return;
            // Store by userId, not socketId
            otherUsers[userData.userId] = {
                username: userData.username,
                publicKey: userData.publicKey,
                userId: userData.userId,
                socketId: userData.id
            };
            addNotification(`${userData.username} joined the chat.`);
            renderUserList();
        });

        socket.on('user left', (socketId) => {
            console.log('User left:', socketId);
            // Find and remove user by socketId
            let removedUserId = null;
            for (const [userId, user] of Object.entries(otherUsers)) {
                if (user.socketId === socketId) {
                    removedUserId = userId;
                    const username = user.username;
                    delete otherUsers[userId];
                    addNotification(`${username} left the chat.`);
                    renderUserList();
                    // If the selected user left, clear the selection
                    if (selectedUser === userId) {
                        selectedUser = null;
                        updateChatUIForMode();
                    }
                    break;
                }
            }
        });

        // Handle incoming secure messages
    socket.on('secure message', handleIncomingMessage);
    }

    // Initialize socket listeners when the chat is first set up
    setupSocketListeners();

    // Handle incoming secure messages
    async function handleIncomingMessage(data) {
        console.log('Received message:', data);
        // Validate message data
        if (!data || !data.encryptedMessage) {
            console.error('Invalid message format:', data);
            return;
        }

        const { from, encryptedKey, encryptedMessage, signature, isGroupMessage, userId } = data;
        const targetWindow = isGroupMessage ? 'group' : 'private';
        let sender = null;
        let senderName = 'Unknown';
        // For group messages, sender is by userId; for private, sender is by socketId
        if (isGroupMessage && userId) {
            sender = otherUsers[userId];
            senderName = sender?.username || 'Unknown';
            // Prevent duplicate group messages: ignore group messages from self (by userId)
            if (userId === myUserId) return;
        } else if (!isGroupMessage && from) {
            // Find user by socketId
            for (const user of Object.values(otherUsers)) {
                if (user.socketId === from) {
                    sender = user;
                    senderName = user.username || 'Unknown';
                    break;
                }
            }
            // Prevent duplicate private messages: ignore messages sent by self
            if (from === socket.id) return;
        }

        try {
            let decryptedMessage;
            let isVerified = false;

            if (isGroupMessage) {
                // For group messages, use the group key
                const decryptedBytes = CryptoJS.AES.decrypt(encryptedMessage, groupKey);
                decryptedMessage = decryptedBytes.toString(CryptoJS.enc.Utf8);

                if (!decryptedMessage) {
                    throw new Error('Failed to decrypt group message');
                }

                // Verify signature if we have the sender's public key
                if (signature && sender?.publicKey) {
                    const verifier = new JSEncrypt();
                    verifier.setPublicKey(sender.publicKey);
                    const hash = CryptoJS.SHA256(decryptedMessage).toString();
                    isVerified = verifier.verify(hash, signature, CryptoJS.SHA256, 'sha256');
                } else if (signature) {
                    console.warn('Cannot verify signature: missing sender public key');
                }
            } else {
                // For private messages, decrypt the session key first
                if (!encryptedKey) {
                    throw new Error('No session key provided for private message');
                }

                const decryptor = new JSEncrypt();
                decryptor.setPrivateKey(chatKeys.private);
                const sessionKeyBase64 = decryptor.decrypt(encryptedKey);

                if (!sessionKeyBase64) {
                    throw new Error('Failed to decrypt session key');
                }

                // Decrypt the message with the session key
                const decryptedBytes = CryptoJS.AES.decrypt(encryptedMessage, sessionKeyBase64);
                decryptedMessage = decryptedBytes.toString(CryptoJS.enc.Utf8);

                if (!decryptedMessage) {
                    throw new Error('Failed to decrypt message with session key');
                }

                // Verify signature if we have the sender's public key
                if (signature && sender?.publicKey) {
                    const verifier = new JSEncrypt();
                    verifier.setPublicKey(sender.publicKey);
                    const hash = CryptoJS.SHA256(decryptedMessage).toString();
                    isVerified = verifier.verify(hash, signature, CryptoJS.SHA256, 'sha256');
                } else if (signature) {
                    console.warn('Cannot verify signature: missing sender public key');
                }
            }

            // Create message data for storage and display
            const messageData = {
                message: decryptedMessage,
                hash: CryptoJS.SHA256(decryptedMessage).toString(),
                encryptedMessage: encryptedMessage,
                signature: signature,
                encryptedKey: encryptedKey,
                isGroupMessage: isGroupMessage,
                timestamp: new Date().toISOString(), // when received
                sender: senderName,
                verified: isVerified,
                sentTimestamp: data.sentTimestamp || null // for latency
            };

            // Add the message to the appropriate chat window
            addChatMessage(
                decryptedMessage,
                senderName,
                false, // isYou
                targetWindow,
                messageData
            );

            if (signature && !isVerified) {
                console.warn('Message signature verification failed');
                addNotification(
                    `Warning: Message from ${senderName} could not be verified`,
                    targetWindow
                );
            }

        } catch (error) {
            console.error('Error processing message:', error);
            addNotification(
                `Error: Could not process message from ${senderName}`,
                targetWindow
            );
        }
    }

    // Set up socket event listeners
    socket.on('disconnect', () => {
        addNotification('Disconnected from server. Attempting to reconnect...', 'system');
    });

    socket.on('connect_error', (error) => {
        console.error('Connection error:', error);
        addNotification('Connection error. Please check your internet connection.', 'system');
    });


    
    const sendSecureMessage = () => {
        const message = chatInput.value;
        if (!message) return;

        if (chatMode === 'private' && !selectedUser) {
            addNotification('Please select a user to send a private message.');
            return;
        }

        if (chatMode === 'group' && Object.keys(otherUsers).length === 0) {
            addNotification('There are no other users to send a group message to.');
            return;
        }

        // For group chat, broadcast a single encrypted message to all (including self)
        if (chatMode === 'group') {
            // Encrypt the message with the static group key
            const encryptedMessage = CryptoJS.AES.encrypt(message, groupKey).toString();
            // Create a digital signature
            const signer = new JSEncrypt();
            signer.setPrivateKey(chatKeys.private);
            const hash = CryptoJS.SHA256(message).toString();
            const signature = signer.sign(hash, CryptoJS.SHA256, 'sha256');
            // Prepare the message to send
            const messageToSend = {
                encryptedMessage: encryptedMessage,
                signature: signature,
                isGroupMessage: true,
                userId: myUserId,
                sentTimestamp: new Date().toISOString() // for latency
            };
            // Add the message to our own chat
            const messageData = {
                message: message,
                hash: hash,
                encryptedMessage: encryptedMessage,
                signature: signature,
                encryptedKey: 'Group messages use the same key',
                timestamp: new Date().toISOString(),
                isGroupMessage: true,
                sentTimestamp: new Date().toISOString() // for latency
            };
            addChatMessage(message, 'You', true, 'group', messageData);
            // Broadcast to all users (including self)
            socket.emit('secure message', messageToSend);
        } else {
            // For private messages, the sendPackageToUser function will handle adding to chat
            sendPackageToUser(selectedUser, message);
        }

        chatInput.value = '';
    };

    const renderUserList = () => {
        if (!userList) return;
        userList.innerHTML = '';
        
        // Add a header
        const header = document.createElement('li');
        header.className = 'font-bold text-gray-300 mb-2';
        header.textContent = 'Online Users:';
        userList.appendChild(header);
        
        // Add users
        for (const id in otherUsers) {
            const user = otherUsers[id];
            const userElement = document.createElement('li');
            userElement.className = 'cursor-pointer p-2 hover:bg-gray-700 rounded flex items-center';
            
            if (selectedUser === id) {
                userElement.classList.add('bg-indigo-900');
            }
            
            // Add user status indicator
            const statusIndicator = document.createElement('span');
            statusIndicator.className = 'inline-block w-2 h-2 rounded-full bg-green-500 mr-2';
            
            // Add username
            const usernameSpan = document.createElement('span');
            usernameSpan.textContent = user.username || 'Unknown';
            
            userElement.appendChild(statusIndicator);
            userElement.appendChild(usernameSpan);
            
            userElement.addEventListener('click', () => {
                selectedUser = id;
                updateChatUIForMode();
            });
            
            userList.appendChild(userElement);
        }
    };

    const updateChatUIForMode = () => {
        if (!userList || !groupChatWindow || !privateChatWindow) return;
        
        const userListContainer = userList.parentElement;
        if (!userListContainer) return;
        
        if (chatMode === 'group') {
            if (chatModeGroupBtn) chatModeGroupBtn.classList.add('active');
            if (chatModePrivateBtn) chatModePrivateBtn.classList.remove('active');
            userListContainer.classList.add('hidden');
            groupChatWindow.classList.remove('hidden');
            privateChatWindow.classList.add('hidden');
            if (chatInput) {
                chatInput.disabled = false;
                chatInput.placeholder = 'Type a message to the group...';
            }
            if (chatSendButton) chatSendButton.disabled = false;
            selectedUser = null; // Deselect user in group mode
        } else { // private
            if (chatModeGroupBtn) chatModeGroupBtn.classList.remove('active');
            if (chatModePrivateBtn) chatModePrivateBtn.classList.add('active');
            userListContainer.classList.remove('hidden');
            groupChatWindow.classList.add('hidden');
            privateChatWindow.classList.remove('hidden');
            
            if (chatInput) {
                if (selectedUser && otherUsers[selectedUser]) {
                    chatInput.disabled = false;
                    chatInput.placeholder = `Message to ${otherUsers[selectedUser].username || 'user'}...`;
                } else {
                    chatInput.disabled = true;
                    chatInput.placeholder = 'Select a user to begin chatting...';
                }
            }
            
            if (chatSendButton) {
                chatSendButton.disabled = !selectedUser;
            }
        }
        renderUserList(); // Re-render to apply selection styles if any
    }

    chatModeGroupBtn.addEventListener('click', () => {
        chatMode = 'group';
        updateChatUIForMode();
    });

    chatModePrivateBtn.addEventListener('click', () => {
        chatMode = 'private';
        updateChatUIForMode();
    });

    // id is userId, not socketId
    const sendPackageToUser = (userId, message) => {
        const recipient = otherUsers[userId];
        if (!recipient) {
            console.error('Recipient not found:', userId);
            return;
        }
        try {
            // 1. Generate a random AES session key
            const sessionKeyBytes = CryptoJS.lib.WordArray.random(32);
            const sessionKeyBase64 = CryptoJS.enc.Base64.stringify(sessionKeyBytes);
            // 2. Encrypt the message with the session key
            const encryptedMessage = CryptoJS.AES.encrypt(message, sessionKeyBase64).toString();
            // 3. Create a digital signature
            const signer = new JSEncrypt();
            signer.setPrivateKey(chatKeys.private);
            const hash = CryptoJS.SHA256(message).toString();
            const signature = signer.sign(hash, CryptoJS.SHA256, 'sha256');
            // 4. Encrypt the session key with the recipient's public key
            const encryptor = new JSEncrypt();
            encryptor.setPublicKey(recipient.publicKey);
            const encryptedKey = encryptor.encrypt(sessionKeyBase64);
            if (!encryptedKey) {
                console.error('Failed to encrypt session key');
                addNotification('Error: Failed to encrypt message.');
                return;
            }
            // Store message data for inspection
            const messageData = {
                message: message,
                hash: hash,
                encryptedMessage: encryptedMessage,
                signature: signature,
                encryptedKey: encryptedKey,
                timestamp: new Date().toISOString(),
                recipient: recipient.username || 'Unknown',
                isGroupMessage: false,
                sentTimestamp: new Date().toISOString() // for latency
            };
            // Add the message to our store with a unique ID
            const messageId = 'msg_' + Date.now();
            messageStore[messageId] = messageData;
            // Prepare the message to send
            const messageToSend = {
                to: userId, // Always userId, not socketId
                encryptedKey: encryptedKey,
                encryptedMessage: encryptedMessage,
                signature: signature,
                isGroupMessage: false,
                messageId: messageId,
                sentTimestamp: new Date().toISOString() // send to recipient
            };
            // Send the message
            socket.emit('secure message', messageToSend);
            // For private messages, add to our own chat
            addChatMessage(message, 'You', true, 'private', messageData);
        } catch (error) {
            console.error(`Failed to send message to ${userId}:`, error);
            addNotification(`Error sending message to ${recipient.username || 'user'}.`);
        }
    };

    chatSendButton.addEventListener('click', sendSecureMessage);
    chatInput.addEventListener('keyup', (event) => {
        if (event.key === 'Enter') {
            sendSecureMessage();
        }
    });

    // Initial state
    updateUI();
});
