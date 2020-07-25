package jp.sbrahma.endpoint;

import javax.servlet.http.HttpServletRequest;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import com.webauthn4j.data.client.challenge.Challenge;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jp.sbrahma.entity.User;
import jp.sbrahma.service.WebAuthnRegistrationService;

@RestController
public class WebAuthnRegistrationRestController {
    private final WebAuthnRegistrationService webAuthnService;

    public WebAuthnRegistrationRestController(WebAuthnRegistrationService webAuthnService) {
        this.webAuthnService = webAuthnService;
    }

    // POST /attestation/options のJSONパラメータ
    private static class AttestationOptionsParam {
        public String email;
    }

    // POST /attestation/result のJSONパラメータ
    private static class AttestationResultParam {
        public byte[] clientDataJSON;
        public byte[] attestationObject;
    }

    // POST /attestation/options のエンドポイント
    @PostMapping(value = "/attestation/options")
    public PublicKeyCredentialCreationOptions postAttestationOptions(@RequestBody AttestationOptionsParam params,
            HttpServletRequest httpRequest) {
        var user = webAuthnService.findOrElseCreate(params.email);
        var options = webAuthnService.creationOptions(user);

        // challengeをHttp Sessionに一時保存
        var session = httpRequest.getSession();
        session.setAttribute("attestationChallenge", options.getChallenge());
        session.setAttribute("attestationUser", user);

        return options;
    }

    // POST /attestation/result のエンドポイント
    @PostMapping(value = "attestation/result")
    public void postAttestationOptions(@RequestBody AttestationResultParam params, HttpServletRequest httpRequest)
            throws JsonProcessingException {
        // HTTPセッションからchallengeを取得
        var httpSession = httpRequest.getSession();
        var challenge = (Challenge) httpSession.getAttribute("attestationChallenge");
        var user = (User) httpSession.getAttribute("attestationUser");

        // 公開鍵クレデンシャルの検証と保存
        webAuthnService.creationFinish(user, challenge, params.clientDataJSON, params.attestationObject);
    }
}