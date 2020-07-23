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