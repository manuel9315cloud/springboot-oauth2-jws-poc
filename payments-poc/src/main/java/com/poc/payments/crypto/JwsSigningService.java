
package com.poc.payments.crypto;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

@Service
public class JwsSigningService {

    private final RSAPrivateKey privateKey;

    public JwsSigningService() throws Exception {

        String pem = Files.readString(
                Path.of("keys/payments-private.pem")
        );

        String privateKeyContent = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder()
                .decode(privateKeyContent);

        PKCS8EncodedKeySpec keySpec =
                new PKCS8EncodedKeySpec(decoded);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        this.privateKey = (RSAPrivateKey)
                keyFactory.generatePrivate(keySpec);
    }

    public String sign(String payload) throws Exception {

        JWSHeader header = new JWSHeader.Builder(
                JWSAlgorithm.RS256
        )
                .type(com.nimbusds.jose.JOSEObjectType.JWT)
                .keyID("payments-key-001")
                .build();

        JWSObject jwsObject = new JWSObject(
                header,
                new Payload(payload)
        );

        jwsObject.sign(new RSASSASigner(privateKey));

        return jwsObject.serialize();
    }
}
