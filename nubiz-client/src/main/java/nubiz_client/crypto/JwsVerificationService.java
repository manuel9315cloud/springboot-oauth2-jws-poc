
package nubiz_client.crypto;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
public class JwsVerificationService {

    private final RSAPublicKey publicKey;

    public JwsVerificationService() throws Exception {

        String pem = Files.readString(
                Path.of("keys/payments-public.pem")
        );

        String publicKeyContent = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder()
                .decode(publicKeyContent);

        X509EncodedKeySpec keySpec =
                new X509EncodedKeySpec(decoded);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        this.publicKey = (RSAPublicKey)
                keyFactory.generatePublic(keySpec);
    }

    public String verifyAndExtractPayload(String signedPayload)
            throws Exception {

        JWSObject jwsObject = JWSObject.parse(signedPayload);

        // Aceptar únicamente RS256
        if (!jwsObject.getHeader()
                .getAlgorithm()
                .getName()
                .equals("RS256")) {
            throw new SecurityException("Unsupported algorithm");
        }

        // Verificar la firma
        boolean valid = jwsObject.verify(
                new RSASSAVerifier(publicKey)
        );

        if (!valid) {
            throw new SecurityException("Invalid JWS signature");
        }

        return jwsObject.getPayload().toString();
    }
}
