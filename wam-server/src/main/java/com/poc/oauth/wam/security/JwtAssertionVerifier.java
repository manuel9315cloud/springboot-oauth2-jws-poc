package com.poc.oauth.wam.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

@Service
public class JwtAssertionVerifier {

    private final RSAPublicKey publicKey;
    private final JtiReplayProtection jtiReplayProtection;

    public JwtAssertionVerifier(JtiReplayProtection jtiReplayProtection) throws Exception {
        this.jtiReplayProtection = jtiReplayProtection;
        this.publicKey = loadPublicKey(
                Path.of("keys/public.pem")
        );
    }

    private RSAPublicKey loadPublicKey(Path path) throws Exception {

        String pem = Files.readString(path);

        String publicKeyContent = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder()
                .decode(publicKeyContent);

        X509EncodedKeySpec keySpec =
                new X509EncodedKeySpec(decoded);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    public boolean verifyAssertion(String token) throws Exception {

        // 1. Parsear el JWT
        SignedJWT signedJWT = SignedJWT.parse(token);

        // 2. Validar algoritmo permitido
        if (!JWSAlgorithm.RS256.equals(signedJWT.getHeader().getAlgorithm())) {
            return false;
        }

        // 3. Verificar firma digital
        JWSVerifier verifier = new RSASSAVerifier(publicKey);

        if (!signedJWT.verify(verifier)) {
            return false;
        }

        // 4. Obtener claims
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        // 5. Validar emisor
        if (!"nubiz-client".equals(claims.getIssuer())) {
            return false;
        }

        // 6. Validar cliente
        if (!"nubiz-client".equals(claims.getSubject())) {
            return false;
        }

        // 7. Validar audiencia
        if (!claims.getAudience().contains(
                "http://localhost:9000/oauth/token")) {
            return false;
        }

        // 8. Validar expiración
        Date expiration = claims.getExpirationTime();

        if (expiration == null ||
                !expiration.toInstant().isAfter(Instant.now())) {
            return false;
        }

        // Validar JTI
        String jti = claims.getJWTID();

        if (jti == null || jti.isBlank()) {
            return false;
        }

        return jtiReplayProtection.register(jti);

    }
}
