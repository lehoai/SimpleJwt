package io.jsonwebtoken;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/**
 * SimpleJwt is a lightweight class for creating and verifying JSON Web Tokens (JWT) without using the
 * complex JJWT library. It focuses on simplicity and supports only the popular HS256 (HMAC-SHA256) algorithm.
 *
 * <p>This class allows you to generate JWT tokens by encoding a header and payload, and signing with a
 * secret key using the HS256 algorithm. Additionally, it provides methods for basic verification of tokens.</p>
 *
 * <p><b>Note:</b> This implementation only supports symmetric signing with a shared secret key and does
 * not include support for other algorithms or key management. For more complex needs, consider using a
 * comprehensive JWT library like JJWT.</p>
 * <p>
 * Dependencies: None
 */
public class SimpleJwt {

    /**
     * Payload to String converter
     */
    public interface PayloadToStrConverter {
        String convertToStr(Object payload);
    }

    /**
     * String to Payload converter
     */
    public interface StrToPayloadConverter {
        Object convertToPayload(String payload);
    }

    /**
     * Abstract class shares methods between JwtBuilder and JwtParser
     */
    static abstract class AbstractJwt {

        protected String createHmacSignature(String data, String secretKey) throws Exception {
            Mac hmacSHA256 = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256");
            hmacSHA256.init(secretKeySpec);
            return base64UrlEncode(hmacSHA256.doFinal(data.getBytes()));
        }

        protected String base64UrlEncode(byte[] data) {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
        }
    }

    /**
     * Jwt token Generator
     */
    public static class JwtBuilder extends AbstractJwt implements PayloadToStrConverter {

        private final PayloadToStrConverter payloadConverter;

        private final static String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";

        /**
         * Default constructor
         * Use default payload converter, which is itself
         */
        public JwtBuilder() {
            this.payloadConverter = this;
        }

        public JwtBuilder(PayloadToStrConverter payloadConverter) {
            this.payloadConverter = payloadConverter;
        }

        public String generateJwt(Object payload, String key) throws Exception {
            // generate header
            String encodedHeader = base64UrlEncode(headerJson.getBytes());

            // generate payload
            String payloadStr = this.payloadConverter.convertToStr(payload);
            String encodedPayload = base64UrlEncode(payloadStr.getBytes());

            // generate message
            String message = encodedHeader + "." + encodedPayload;

            // generate signature
            String signature = createHmacSignature(message, key);

            return message + "." + signature;
        }


        @Override
        public String convertToStr(Object payload) {
            return payload.toString();
        }
    }


    /**
     * Jwt token Parser
     */
    public static class JwtParser extends AbstractJwt implements StrToPayloadConverter {

        private final StrToPayloadConverter strToPayloadConverter;

        public JwtParser() {
            this.strToPayloadConverter = this;
        }

        public JwtParser(StrToPayloadConverter strToPayloadConverter) {
            this.strToPayloadConverter = strToPayloadConverter;
        }

        /**
         * verify jwt token
         */
        public boolean verifyToken(String token, String key) throws Exception {

            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                return false;
            }
            String headerAndPayload = parts[0] + "." + parts[1];
            String signature = parts[2];

            // Recreate the signature using the provided secret key
            String expectedSignature = createHmacSignature(headerAndPayload, key);

            // Compare the provided signature with the expected signature

            return signature.equals(expectedSignature);
        }

        public Object getPayload(String token) throws Exception {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                throw new IllegalArgumentException("Invalid JWT token format.");
            }
            String encodedPayload = parts[1];
            byte[] decodedBytes = Base64.getUrlDecoder().decode(encodedPayload);
            String payloadStr = new String(decodedBytes);

            return strToPayloadConverter.convertToPayload(payloadStr);
        }

        @Override
        public Object convertToPayload(String payload) {
            return payload;
        }
    }
}
