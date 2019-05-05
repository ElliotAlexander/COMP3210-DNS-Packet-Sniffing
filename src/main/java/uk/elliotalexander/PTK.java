package uk.elliotalexander;

import com.google.common.io.BaseEncoding;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class PTK {
    private static final String HMAC_SHA1 = "HmacSHA1";

    private static String HSHA1(String key, String purpose, String data, String length) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1);
        Mac mac = Mac.getInstance(HMAC_SHA1);
        mac.init(signingKey);

        String payload = purpose + "0" + data + length;

        return BaseEncoding.base16().encode(mac.doFinal(payload.getBytes()));
    }

    private static String PRF(String key, String purpose, String data, int length) throws InvalidKeyException, NoSuchAlgorithmException {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i <= (length+159)/160; i++) {
            result.append(HSHA1(key, purpose, data, Integer.toString(i)));
        }

        return result.toString().substring(0, length/4);
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

    public static void main(String[] args) throws Exception {
/*        final String AA = "44:85:00:dc:39:ee";
        final String SPA = "e4:95:6e:44:00:e6";
        final String ANonce = "cbc4f0a9f9879a00ef6317c7d67300c20db915717c8180991d2a99a054679dee";
        final String SNonce = "bd2735ca00654390ef452863d853d2d2760c36c85997af77c05ca33a272ec55c";
        final String PMK = "8c36c8f2e805fea9e153ff1ed457b3c1cf87f428de5432566b77e7e91a8ab5aa";

        String ptk = buildPTK(PMK, AA, SPA, ANonce, SNonce);
        System.out.println("DERIVED PTK = " + ptk);
        System.out.println(ptk.length());

        // 32 Characters
        // From 64 to 32
        StringBuilder ccmpKeyBuilder = new StringBuilder();
        ccmpKeyBuilder.append(ptk.substring(32, 64));

        final String ccmpKey = ccmpKeyBuilder.reverse().toString();*/

        //final byte[] ccmKeyBytes = BaseEncoding.base16().decode("5ced6b863fccfc3e0e51837cd5fec81d".toUpperCase());


        /*
         * EXAMPLE FROM H.6.4 ON SPEC
         */

        final byte[] ccmKeyBytes = BaseEncoding.base16().decode("c97c1f67ce371185514a8a19f2bdd52f".toUpperCase());

        Security.addProvider(new BouncyCastleProvider());
        AEADParameters params = new AEADParameters(new KeyParameter(ccmKeyBytes), 64, BaseEncoding.base16().decode("005030f1844408b5039776e70c".toUpperCase()), new byte[]{});
        CCMBlockCipher c = new CCMBlockCipher(new AESEngine());
        c.init(false, params);

        final String encrypted = "f3d0a2fe9a3dbf2342a643e43246e80c3c04d0197845ce0b16f97623";
        byte[] encryptedBytes = BaseEncoding.base16().decode(encrypted.toUpperCase());

        byte[] outputBytes = new byte[c.getOutputSize(encryptedBytes.length)];
        int result = c.processBytes(encryptedBytes, 0, encryptedBytes.length, outputBytes, 0);
        try {
            c.doFinal(outputBytes, result);
        } catch (Exception e) {

        }
        System.out.println(BaseEncoding.base16().encode(outputBytes));
    }
}