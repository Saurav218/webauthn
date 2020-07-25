package jp.sbrahma.endpoint;

import javax.servlet.http.HttpServletRequest;

import com.webauthn4j.data.PublicKeyCredentialRequestOptions;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jp.sbrahma.service.WebAuthnAuthenticationService;

@RestController
public class WebAuthnAuthenticationRestController {
    private final WebAuthnAuthenticationService webAuthnService;

    public WebAuthnAuthenticationRestController(WebAuthnAuthenticationService webAuthnService) {
        this.webAuthnService = webAuthnService;
    }

    // POST /assertion/options のJSONパラメータ
    private static class AssertionOptionsParam {
        public String email;
    }

    // POST /assertion/options のエンドポイントを設定
    @PostMapping(value = "/assertion/options")
    public PublicKeyCredentialRequestOptions postAssertionOptions(
        @RequestBody AssertionOptionsParam params,
        HttpServletRequest httpRequest
    ) {
        var user = webAuthnService.find(params.email).orElseThrow();
        var options = webAuthnService.requestOptions(user);

        // チャレンジをHTTP Sessionに一時保存
        var session = httpRequest.getSession();
        session.setAttribute("assertionChallenge", options.getChallenge());
        return options;
    }
}