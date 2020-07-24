package jp.sbrahma.endpoint;

import javax.servlet.http.HttpServletRequest;

import com.webauthn4j.data.PublicKeyCredentialCreationOptions;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

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

    // POST /attestation/options のエンドポイント
    @PostMapping(value = "/attestation/options")
    public PublicKeyCredentialCreationOptions postAttestationOptions(
        @RequestBody AttestationOptionsParam params,
        HttpServletRequest httpRequest
    ) {
        var user = webAuthnService.findOrElseCreate(params.email);
        var options = webAuthnService.creationOptions(user);

        // challengeをHttp Sessionに一時保存
        var session = httpRequest.getSession();
        session.setAttribute("attestationChallenge", options.getChallenge());
        session.setAttribute("attestationUser", user);

        return options;
    }
}