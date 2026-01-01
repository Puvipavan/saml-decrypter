function clearLogs() {
    document.getElementById('logs').innerHTML = '';
    document.getElementById('copy_decrypted_assertion').disabled = true;
    document.getElementById("decrypted_assertion").value = "";
}

function appendLog(message, showAlert = false) {
    let p = document.createElement('p');
    p.innerText = message;
    document.getElementById('logs').appendChild(p);

    if (showAlert) {
        alert(message);
    }
}

function isSupportedDigest(digest) {
    if (digest.includes('sha1')) {
        return 'sha-1';
    } else if (digest.includes('sha256')) {
        return 'sha-256';
    } else if (digest.includes('sha384')) {
        return 'sha-384';
    } else if (digest.includes('sha512')) {
        return 'sha-512';
    }
    return false;
}

function isSupportedAlgorithm(algorithm) {
    if (algorithm == 'http://www.w3.org/2009/xmlenc11#aes128-gcm') {
        return 'aes128-gcm';
    } else if (algorithm == 'http://www.w3.org/2009/xmlenc11#aes192-gcm') {
        return 'aes192-gcm';
    } else if (algorithm == 'http://www.w3.org/2009/xmlenc11#aes256-gcm') {
        return 'aes256-gcm';
    } else if (algorithm == 'http://www.w3.org/2001/04/xmlenc#aes128-cbc') {
        return 'aes128-cbc';
    } else if (algorithm == 'http://www.w3.org/2001/04/xmlenc#aes192-cbc') {
        return 'aes192-cbc';
    } else if (algorithm == 'http://www.w3.org/2001/04/xmlenc#aes256-cbc') {
        return 'aes256-cbc';
    }
    return false;
}

function isSupportedRSAEncryptionAlgorithm(algorithm) {
    if (algorithm.includes('rsa-oaep')) {
        return 'rsa-oaep';
    } else if (algorithm.includes('rsassa-pkcs1-v1_5')) {
        return 'rsassa-pkcs1-v1_5';
    }
    return false;
}

function nsResolver(prefix) {
    let namespaces = {
        "saml2": "urn:oasis:names:tc:SAML:2.0:assertion",
        "xenc": "http://www.w3.org/2001/04/xmlenc#",
        "ds": "http://www.w3.org/2000/09/xmldsig#"
    };
    return namespaces[prefix] || null;
}

function extractData() {
    clearLogs();
    let xmlAssertion = document.getElementById('xml_assertion').value.trim();

    if (!xmlAssertion) {
        alert('Please provide XML assertion');
        return;
    }
    appendLog('Parsing XML...');
    let parser = new DOMParser();
    let xmlDoc = parser.parseFromString(xmlAssertion, "text/xml");
    appendLog('Parsing Success.');

    appendLog('Searching for EncryptedAssertion element in saml2 namespace...');
    let encryptedAssertion = xmlDoc.evaluate("//saml2:EncryptedAssertion", xmlDoc, nsResolver, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

    if (!encryptedAssertion) {
        appendLog('EncryptedAssertion element in saml2 namespace is not found in the XML', true);
        return;
    }

    appendLog('Found EncryptedAssertion element in xenc namespace.');
    appendLog('Searching for EncryptedData element in xenc namespace...');
    let encryptedData = xmlDoc.evaluate("//xenc:EncryptedData", xmlDoc, nsResolver, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

    if (!encryptedData) {
        appendLog('EncryptedData element in xenc namespace is not found in the XML.', true);
        return;
    }

    appendLog('Found EncryptedData in xenc namespace.');
    appendLog('Searching for EncryptionMethod element in xenc namespace...');
    let encryptionMethod = xmlDoc.evaluate("//xenc:EncryptionMethod", xmlDoc, nsResolver, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

    if (!encryptionMethod) {
        appendLog('EncryptionMethod element in xenc namespace is not found.', true);
        return;
    }

    appendLog('Found EncryptionMethod element in xenc namespace.');
    appendLog('Checking for Algorithm attribute in EncryptionMethod element...');
    let algorithm = encryptionMethod.getAttribute("Algorithm");

    if (!algorithm) {
        alert('Algorithm attribute not found in EncryptionMethod element');
        appendLog('Algorithm attribute not found.');
        return;
    }

    appendLog(`Data Encryption Algorithm: ${algorithm}`);

    let supportedAlgorithm = isSupportedAlgorithm(algorithm);

    if (!supportedAlgorithm) {
        appendLog(`We do not support the algorithm: ${algorithm}`, true);
        return;
    }

    document.getElementById('encryption_algorithm_data').value = supportedAlgorithm;

    appendLog('Searching for //xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod ...');
    let encryptionMethodKey = xmlDoc.evaluate("//xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod", xmlDoc, nsResolver, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

    if (!encryptionMethodKey) {
        appendLog('//xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod not found in the XML', true);
        return;
    }

    appendLog('Found //xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod.');
    appendLog('Checking for Algorithm attribute...');
    let rsaAlgorithm = encryptionMethodKey.getAttribute("Algorithm");

    if (!rsaAlgorithm) {
        appendLog('Algorithm attribute not found in //xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod.', true);
        return;
    }

    appendLog(`Encryption Algorithm(Key): ${rsaAlgorithm}`);

    let supportedRSAAlgorithm = isSupportedRSAEncryptionAlgorithm(rsaAlgorithm);

    if (!supportedRSAAlgorithm) {
        appendLog(`We do not support the algorithm: ${rsaAlgorithm}`, true);
        return;
    }

    document.getElementById('encryption_algorithm_key').value = supportedRSAAlgorithm;

    appendLog('Searching for //xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/ds:DigestMethod ...');
    let encryptionKeyAlgorithmDigest = xmlDoc.evaluate("//xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/ds:DigestMethod", xmlDoc, nsResolver, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

    if (!encryptionKeyAlgorithmDigest) {
        appendLog('//xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/ds:DigestMethod not found in the XML', true);
        return;
    }

    appendLog('Found //xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/ds:DigestMethod');
    appendLog('Checking for Algorithm attribute...');
    let digest = encryptionKeyAlgorithmDigest.getAttribute("Algorithm");

    if (!digest) {
        appendLog('Algorithm attribute not found in //xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/ds:DigestMethod', true);
        return;
    }

    appendLog(`Encryption Algorithm(Key) Digest: ${digest}`);

    let supportedDigest = isSupportedDigest(digest);

    if (!supportedDigest) {
        appendLog(`We do not support the digest: ${digest}`, true);
        return;
    }

    document.getElementById('encryption_digest_method').value = supportedDigest;

    appendLog('Searching for Encrypted Key(Base64)...');
    let encryptedKey = xmlDoc.evaluate("//xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue", xmlDoc, nsResolver, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue.textContent;

    if (!encryptedKey) {
        appendLog('Unable to find EncryptedKey');
        return;
    }

    appendLog('Found EncryptedKey.');
    document.getElementById('encrypted_key').value = encryptedKey;

    appendLog('Searching for Encrypted Assertion(Base64)...');
    encryptedAssertion = xmlDoc.evaluate("//xenc:EncryptedData/xenc:CipherData/xenc:CipherValue", xmlDoc, nsResolver, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue.textContent;

    if (!encryptedAssertion) {
        appendLog('Unable to find Encrypted Assertion', true);
        return;
    }

    appendLog('Found Encrypted Assertion(Base64).');
    document.getElementById('encrypted_assertion').value = encryptedAssertion;

    decryptData(false);
}

async function decryptData(clear = true) {
    let spPrivateKey = document.getElementById('sp_private_key').value.trim();
    let encryptionAlgorithmData = document.getElementById('encryption_algorithm_data').value.trim();
    let encryptedKey = document.getElementById('encrypted_key').value.trim();
    let encryptedAssertion = document.getElementById('encrypted_assertion').value.trim();
    let encryptionAlgorithmKey = document.getElementById('encryption_algorithm_key').value.trim();
    let encryptionDigestMethod = document.getElementById('encryption_digest_method').value.trim();

    if (clear) {
        clearLogs();
    }

    if (!spPrivateKey) {
        alert('Please provide SP private key');
        return;
    }

    if (!encryptionAlgorithmData) {
        alert('Please select Encryption Algorithm(Data)');
        return;
    }

    if (!encryptedKey) {
        alert('Please provide Encrypted Key(Base64)');
        return;
    }

    if (!encryptedAssertion) {
        alert('Please provide Encrypted Assertion(Base64)');
        return;
    }

    if (!encryptionAlgorithmKey) {
        alert('Please select Encryption Algorithm(Key)');
        return;
    }

    if (!encryptionDigestMethod) {
        alert('Please select Encryption Algorithm(Key) Digest');
        return;
    }

    appendLog('Decrypting Encrypted Key Using Private Key...');
    let decryptedKey;
    try {
        decryptedKey = await wasmDecryptRSA(spPrivateKey, encryptedKey, encryptionDigestMethod, encryptionAlgorithmKey);
        if (decryptedKey["error"]) {
            appendLog('Key Decryption Failed. Error: ' + decryptedKey["msg"], true);
            return;
        }
        decryptedKey = decryptedKey["data"];
    } catch (e) {
        appendLog('Key Decryption Failed. Please check the private key and make sure it\'s in PKCS1/PKCS8 PEM Encoded format or contact us. ' + e, true);
        return;
    }

    appendLog(`Key Decryption Success. Key(Base64): ${decryptedKey}`);

    let decryptedData;
    if (encryptionAlgorithmData.includes('cbc')) {
        appendLog('Decrypting Encrypted Assertion Data Using AES-CBC...');
        decryptedData = await wasmDecryptAESCBC(encryptedAssertion, decryptedKey);
    } else if (encryptionAlgorithmData.includes('gcm')) {
        appendLog('Decrypting Encrypted Assertion Data Using AES-GCM...');
        decryptedData = await wasmDecryptAESGCM(encryptedAssertion, decryptedKey);
    } else {
        appendLog('We do not support the algorithm', true);
        return;
    }

    if (decryptedData["error"]) {
        appendLog('Decryption Failed. Error: ' + decryptedData["msg"], true);
        return;
    }

    decryptedData = decryptedData["data"];

    appendLog(`Decryption Success. Check the output below.`, true);
    document.getElementById('copy_decrypted_assertion').disabled = false;
    document.getElementById("decrypted_assertion").value = decryptedData;
    document.getElementById("decrypted_assertion").style.height = '35em';
    document.getElementById("decrypted_assertion_section").scrollIntoView();
}

function copyAssertion() {
    navigator.clipboard.writeText(document.getElementById("decrypted_assertion").value).then(() => {
        alert('Decrypted Assertion copied to clipboard!');
    }).catch(err => {
        alert('Failed to copy Decrypted Assertion: ' + err);
    });
}

document.addEventListener('DOMContentLoaded', (event) => {
    document.getElementById('extract_data').addEventListener('click', () => {
        extractData();
    });

    document.getElementById('decrypt').addEventListener('click', () => {
        decryptData();
    });

    document.getElementById('copy_decrypted_assertion').addEventListener('click', () => {
        copyAssertion();
    });
});
