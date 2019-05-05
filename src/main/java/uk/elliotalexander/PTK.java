package uk.elliotalexander;

import com.google.common.io.BaseEncoding;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class PTK {
    private static final String HMAC_SHA1 = "HmacSHA1";

    private static String HSHA1(byte[] key, byte[] purpose, byte[] data, byte length) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] input = Arrays.concatenate(purpose, new byte[]{0}, data, new byte[]{length});

        SecretKeySpec signingKey = new SecretKeySpec(key, HMAC_SHA1);
        Mac mac = Mac.getInstance(HMAC_SHA1);
        mac.init(signingKey);

        return BaseEncoding.base16().encode(mac.doFinal(input));
    }

    private static String PRF(byte[] key, byte[] purpose, byte[] data, int length) throws InvalidKeyException, NoSuchAlgorithmException {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i <= (length+159)/160; i++) {
            result.append(HSHA1(key, purpose, data, (byte) i));
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

        byte[] params = BaseEncoding.base16().decode((a+nonce).toUpperCase());

        return PRF(PMK.getBytes(), "Pairwise key expansion".getBytes(), params, 384);
    }

    public static void main(String[] args) throws Exception {
        /*
         * TEST FROM H.7.1 ON SPEC
         */
        final String AA = "a0a1a1a3a4a5";
        final String SPA = "b0b1b2b3b4b5";
        final String ANonce = "e0e1e2e3e4e5e6e7e8e9f0f1f2f3f4f5f6f7f8f9";
        final String SNonce = "c0c1c2c3c4c5c6c7c8c9d0d1d2d3d4d5d6d7d8d9";
        final String PMK = "0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af";

        String ptk = buildPTK(PMK, AA, SPA, ANonce, SNonce);

        // 32 Characters
        // From 64 to 32
        StringBuilder ccmpKeyBuilder = new StringBuilder();
        ccmpKeyBuilder.append(ptk, 32, 64);

        final String ccmpKey = ccmpKeyBuilder.reverse().toString();
        System.out.println("CCM KEY: " + ccmpKey);



        /*
         * DECRYPTED PACKET 12246 FROM WIRESHARK
         */
        final byte[] ccmKeyBytes = BaseEncoding.base16().decode("5ced6b863fccfc3e0e51837cd5fec81d".toUpperCase());
        Security.addProvider(new BouncyCastleProvider());
        byte[] nonce = BaseEncoding.base16().decode("00448500dc39ee00000000028a".toUpperCase());

        AEADParameters params = new AEADParameters(new KeyParameter(ccmKeyBytes), 64, nonce, new byte[]{});
        CCMBlockCipher c = new CCMBlockCipher(new AESEngine());
        c.init(false, params);

        final String encrypted = "39f7b6a6ec785448b1d28f563e62b7d53b571038ba9d83d11a2a3aa4ea226094b6b4a41b2bf400b3f0534ebfc76b93f96857e5a3e255f112870986453aca5cba0332a8a21e0317177c3d21117e72a8982409f92853c436e15eb48d";
        byte[] encryptedBytes = BaseEncoding.base16().decode(encrypted.toUpperCase());

        byte[] outputBytes = new byte[c.getOutputSize(encryptedBytes.length)];
        int result = c.processBytes(encryptedBytes, 0, encryptedBytes.length, outputBytes, 0);
        try {
            c.doFinal(outputBytes, result);
        } catch (Exception e) {

        }
        System.out.println("DECRYPTED PACKET: " + BaseEncoding.base16().encode(outputBytes));
    }
}