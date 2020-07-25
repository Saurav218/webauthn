package jp.sbrahma.service;

import java.io.IOException;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collector;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.UserVerificationRequirement;
import com.webauthn4j.data.WebAuthnAuthenticationContext;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.PublicKeyCredentialRequestOptions;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;

import org.springframework.stereotype.Service;
import jp.sbrahma.repository.UserRepository;
import jp.sbrahma.entity.User;
import jp.sbrahma.repository.CredentialRepository;

@Service
public class WebAuthnAuthenticationService {
    private final UserRepository userRepository;
    private final CredentialRepository credentialRepository;

    public WebAuthnAuthenticationService(UserRepository userRepository, CredentialRepository credentialRepository) {
        this.userRepository = userRepository;
        this.credentialRepository = credentialRepository;
    }

    public Optional<User> find(String email) {
        return userRepository.find(email);
    }

    public PublicKeyCredentialRequestOptions requestOptions(User user) {
        // challenge(リプレイ攻撃回避)
        var challenge = new DefaultChallenge();

        // timeout(認証のタイムアウト(ms))
        var timeout = 120000L;

        // rpId(中間者攻撃を回避するRPサーバの有効ドメインを指定)
        var rpId = "localhost";

        // allowCredentials(RPサーバに登録されたCredentialIDの一覧)
        var credentials = credentialRepository.finds(user.getId());
        var allowCredentials = credentials.stream()
                .map(credential -> new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY,
                        credential.getCredentialId(), Set.of()))
                .collect(Collectors.toList());

        // userVerification(認証器の生体認証やPINを要求)
        var userVerification = UserVerificationRequirement.REQUIRED;

        // 公開鍵クレデンシャル要求API(navigator.credentials.get)のパラメータを作成
        return new PublicKeyCredentialRequestOptions(challenge, timeout, rpId, allowCredentials, userVerification,
                null);
    }

    public void assertionFinish(Challenge challenge, byte[] credentialId, byte[] clientDataJSON,
            byte[] authenticatorData, byte[] signature) throws IOException {
        // originの検証(中間者攻撃耐性)
        var origin = Origin.create("http://localhost:8080");

        // rpIdHashの検証(中間者攻撃耐性)
        var rpId = "localhost";

        // challengeの検証(リプレイ攻撃耐性)
        var challengeBase64 = new DefaultChallenge(Base64.getEncoder().encode(challenge.getValue()));

        var serverProperty = new ServerProperty(origin, rpId, challengeBase64, null);

        // flagsの検証(ユーザ検証)
        var userVerificationRequired = true;

        var authenticationContext = new WebAuthnAuthenticationContext(credentialId, clientDataJSON, authenticatorData,
                signature, serverProperty, userVerificationRequired);

        // DBから登録済みの公開鍵を取得
        var credential = credentialRepository.find(credentialId).orElseThrow();

        // 公開鍵をバイナリからデシリアライズ
        var publicKey = new ObjectMapper().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .readValue(credential.getPublicKey(), COSEKey.class);

        // 検証用に認証器を復元
        AAGUID aaguid = null;
        AttestationStatement attestationStatement = null;
        var authenticator = new AuthenticatorImpl(new AttestedCredentialData(aaguid, credentialId, publicKey), attestationStatement, credential.getSignatureCounter());
        var validator = new WebAuthnAuthenticationContextValidator();

        // signatureの検証(公開鍵による署名の検証)
        // signCountの検証(クローンの認証器の検出)
        var response = validator.validate(authenticationContext, authenticator);

        // 署名カウンタの更新
        var currentCounter = response.getAuthenticatorData().getSignCount();
        credential.setSignatureCounter(currentCounter);
        credentialRepository.update(credential);
    }
}