package uk.elliotalexander;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class PTK {
    private static final String HMAC_SHA1 = "HmacSHA1";

    private static String byteToHex(byte[] data) {
        final StringBuilder builder = new StringBuilder();

        for (byte b : data) {
            builder.append(String.format("%02x", b));
        }

        return builder.toString();
    }

    private static String HSHA1(String key, String purpose, String data, String length) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1);
        Mac mac = Mac.getInstance(HMAC_SHA1);
        mac.init(signingKey);

        String payload = purpose + "0" + data + length;

        return byteToHex(mac.doFinal(payload.getBytes()));
    }

    private static String PRF(String key, String purpose, String data, int length) throws InvalidKeyException, NoSuchAlgorithmException {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i <= (length+159)/160; i++) {
            result.append(HSHA1(key, purpose, data, Integer.toString(i)));
        }

        return result.toString();
    }

    public static String buildPTK(String PMK, String AA, String SPA, String ANonce, String SNonce) throws NoSuchAlgorithmException, InvalidKeyException {
        String a;
        if (AA.compareTo(SPA) < 0) {
            a = AA + SPA;
        } else {
            a = SPA + AA;
        }

        String nonce;
        if (ANonce.compareTo(SNonce) < 0) {
            nonce = ANonce + SNonce;
        } else {
            nonce = SNonce + ANonce;
        }

        return PRF(PMK, "Pairwise key expansion", a+nonce, 384);
    }
}
