// 登録
async function registerAsync() {
    try {
        // RPサーバから公開鍵クレデンシャル生成オプションを取得
        const optionsRes = await postAttestationOptions();
        const optionsJSON = await optionsRes.json();

        // 認証器からAttestationResponseを取得
        const credential = await createCredential(optionsJSON);

        // RPサーバにAttestationResponseを送信
        const response = await registerFinish(credential);

        // ログインページへ移動
        redirectToSignInPage(response);
    } catch (error) {
        alert(error);
    }
}

function postAttestationOptions() {
    const url = '/attestation/options';
    const data = {
        'email': document.getElementById('email').value
    };

    return fetch(url, {
        method: 'POST',
        body: JSON.stringify(data),
        headers: {
            'Content-Type': 'application/json'
        }
    });
}

function createCredential(options) {
    // ArrayBufferに変換
    options.challenge = stringToArrayBuffer(options.challenge.value)
    options.user.id = stringToArrayBuffer(options.user.id)
    options.excludeCredentials = options.excludeCredentials
        .map(credential => Object.assign({}, credential, {
            id: base64ToArrayBuffer(credential.id)
        }))

    // 認証器からAttestationResponseを取得するWebAuthn API
    return navigator.credentials.create({
        'publicKey': options
    });
}

function registerFinish(credential) {
    const url = '/attestation/result';
    const data = {
        'clientDataJSON': arrayBufferToBase64(credential.response.clientDataJSON),
        'attestationObject': arrayBufferToBase64(credential.response.attestationObject),
    };

    return fetch(url, {
        method: 'POST',
        body: JSON.stringify(data),
        headers: {
            'Content-Type': 'application/json'
        }
    });
}

// 文字列をArrayBufferに変換
function stringToArrayBuffer(string) {
    return new TextEncoder().encode(string);
}

// Base64文字列をArrayBufferにデコード
function base64ToArrayBuffer(base64String) {
    return Uint8Array.from(atob(base64String), c => c.charCodeAt(0));
}

// ArrayBufferをBase64文字列にエンコード
function arrayBufferToBase64(arrayBuffer) {
    return btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
}

// 認証
async function authenticationAsync() {
    try {
        // RPサーバから公開鍵クレデンシャル要求オプションを取得
        const optionsRes = await postAssertionOptions();
        const optionsJSON = await optionsRes.json();

        // 認証器からAssertionResponseを取得
        const response = await authenticationFinish(assertion);
        signedIn(response);
    } catch (error) {
        alert(error);
    }
}

function postAssertionOptions() {
    const url = '/assertion/options';
    const data = {
        'email': document.getElementById('email').value
    };

    return fetch(url, {
        method: 'POST',
        body: JSON.stringify(data),
        headers: {
            'Content-Type': 'application/json'
        }
    });
}