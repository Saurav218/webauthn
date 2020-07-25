package jp.sbrahma.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.data.AttestationConveyancePreference;
import com.webauthn4j.data.AuthenticatorAttachment;
import com.webauthn4j.data.AuthenticatorSelectionCriteria;
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialRpEntity;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.PublicKeyCredentialUserEntity;
import com.webauthn4j.data.UserVerificationRequirement;
import com.webauthn4j.data.WebAuthnRegistrationContext;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import org.springframework.stereotype.Service;

import jp.sbrahma.repository.CredentialRepository;
import jp.sbrahma.repository.UserRepository;
import jp.sbrahma.entity.Credential;
import jp.sbrahma.entity.User;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collector;
import java.util.stream.Collectors;

@Service
public class WebAuthnRegistrationService {
    private final UserRepository userRepository;
    private final CredentialRepository credentialRepository;

    public WebAuthnRegistrationService(UserRepository userRepository, CredentialRepository credentialRepository) {
        this.userRepository = userRepository;
        this.credentialRepository = credentialRepository;
    }

    public PublicKeyCredentialCreationOptions creationOptions(User user) {
        // rp(中間者攻撃を回避するRPサーバ情報)
        var rpId = "localhost";
        var rpName = "Saurav WebAuthn Test";
        var rp = new PublicKeyCredentialRpEntity(rpId, rpName);

        // user(ユーザ情報)
        var userId = user.getId();
        var userName = user.getEmail();
        var userDisplayName = "";
        var userInfo = new PublicKeyCredentialUserEntity(userId, userName, userDisplayName);

        // challenge(リプレイ攻撃を回避する乱数)
        var challenge = new DefaultChallenge();

        // pubKeyCredParams(クレデンシャル生成方法の要求事項)
        var es256 = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY,
                COSEAlgorithmIdentifier.ES256);
        var rs256 = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY,
                COSEAlgorithmIdentifier.RS256);
        var pubKeyCredParams = List.of(es256, rs256);

        // timeout(登録のタイムアウト時間(ms))
        var timeout = 120000L;

        // excludeCredentials(同一認証器の登録制限)
        var credentials = credentialRepository.finds(userId);
        var excludeCredentials = credentials.stream()
                .map(credential -> new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY,
                        credential.getCredentialId(), Set.of()))
                .collect(Collectors.toList());

        // authenticatorSelection(認証器の要求事項)
        var authenticatorAttachment = AuthenticatorAttachment.PLATFORM;
        var requireResidentKey = false;
        var userVerification = UserVerificationRequirement.REQUIRED;
        var authenticatorSelection = new AuthenticatorSelectionCriteria(authenticatorAttachment, requireResidentKey,
                userVerification);

        // attestation(認証器のAttestationを要求)
        var attestation = AttestationConveyancePreference.NONE;

        // 公開鍵クレデンシャル生成API(navigator.credentials.create)のパラメータを作成
        return new PublicKeyCredentialCreationOptions(rp, userInfo, challenge, pubKeyCredParams, timeout,
                excludeCredentials, authenticatorSelection, attestation, null);
    }

    public User findOrElseCreate(String email) {
        return userRepository.find(email).orElseGet(() -> createUser(email));
    }

    private User createUser(String email) {
        // 個人が特定できない最大64バイトのランダムなバイト列
        var userId = new byte[32];
        new SecureRandom().nextBytes(userId);

        var user = new User();
        user.setId(userId);
        user.setEmail(email);
        return user;
    }

    private void creationFinish(User user, Challenge challenge, byte[] clientDataJSON, byte[] attestationObject)
            throws JsonProcessingException {
        // originの検証(中間者攻撃耐性)
        var origin = Origin.create("http://localhost:8080");

        // rpIdHashの検証(中間者攻撃耐性)
        var rpId = "localhost";

        // challengeの検証(リプレイ攻撃耐性)
        var challengeBase64 = new DefaultChallenge(Base64.getEncoder().encode(challenge.getValue()));

        var serverProperty = new ServerProperty(origin, rpId, challengeBase64, null);

        // flagsの検証(ユーザ検証->多要素認証)
        var userVerificationRequired = true;

        var registrationContext = new WebAuthnRegistrationContext(clientDataJSON, attestationObject, serverProperty, userVerificationRequired);

        // AttestationStatementは検証しない
        var validator = WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator();

        // clientDataJSONの検証(クレデンシャルの生成に渡されたデータ)
        // attestationObjectの検証(認証器の検証)
        var response = validator.validate(registrationContext);

        // DBに保存する最低限の公開鍵クレデンシャルを取得
        var credentialId = response.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getCredentialId();

        var publicKey = response.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getCOSEKey();

        var signatureCounter = response.getAttestationObject().getAuthenticatorData().getSignCount();

        // ユーザ作成
        if (userRepository.find(user.getEmail()).isEmpty()) {
            userRepository.insert(user);
        }

        // 公開鍵を保存用にバイナリ化
        var publicKeyBin = new ObjectMapper().writeValueAsBytes(publicKey);

        // 公開鍵クレデンシャルの保存
        var credential = new Credential();
        credential.setCredentialId(credentialId);
        credential.setUserId(user.getId());
        credential.setPublicKey(publicKeyBin);
        credential.setSignatureCounter(signatureCounter);
        credentialRepository.insert(credential);
    }
}