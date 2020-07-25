package jp.sbrahma.service;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collector;
import java.util.stream.Collectors;

import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.UserVerificationRequirement;
import com.webauthn4j.data.PublicKeyCredentialRequestOptions;
import com.webauthn4j.data.client.challenge.DefaultChallenge;

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
        return new PublicKeyCredentialRequestOptions(challenge, timeout, rpId, allowCredentials, userVerification, null);
    }
}