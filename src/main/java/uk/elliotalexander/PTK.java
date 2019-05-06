package uk.elliotalexander;

import com.google.common.io.BaseEncoding;
import com.google.common.primitives.UnsignedBytes;
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

    private static byte[] HSHA1(byte[] key, byte[] purpose, byte[] data, byte length) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] input = Arrays.concatenate(purpose, new byte[]{0}, data, new byte[]{length});

        SecretKeySpec signingKey = new SecretKeySpec(key, HMAC_SHA1);
        Mac mac = Mac.getInstance(HMAC_SHA1);
        mac.init(signingKey);

        return mac.doFinal(input);
    }

    private static byte[] PRF(byte[] key, byte[] purpose, byte[] data, int length) throws InvalidKeyException, NoSuchAlgorithmException {
        byte[] result = new byte[]{};
        for (int i = 0; i <= (length+159)/160; i++) {
            result = Arrays.concatenate(result, HSHA1(key, purpose, data, (byte) i));
        }

        return result;
    }

    public static byte[] buildPTK(byte[] PMK, byte[] AA, byte[] SPA, byte[] ANonce, byte[] SNonce) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] a;
        if (UnsignedBytes.lexicographicalComparator().compare(AA, SPA) < 0) {
            a = Arrays.concatenate(AA, SPA);
        } else {
            a = Arrays.concatenate(SPA, AA);
        }

        byte[] nonce;
        if (UnsignedBytes.lexicographicalComparator().compare(ANonce, SNonce) < 0) {
            nonce = Arrays.concatenate(ANonce, SNonce);
        } else {
            nonce = Arrays.concatenate(SNonce, ANonce);
        }

        byte[] data = Arrays.concatenate(a, nonce);

        return PRF(PMK, "Pairwise key expansion".getBytes(), data, 384);
    }

    public static void main(String[] args) throws Exception {
        /*
         * EAPOL HANDSHAKE AT 9545
         */

        final byte[] AA = BaseEncoding.base16().decode("e4956e4400e6".toUpperCase());
        final byte[] SPA = BaseEncoding.base16().decode("448500dc39ee".toUpperCase());
        final byte[] ANonce = BaseEncoding.base16().decode("cbc4f0a9f9879a00ef6317c7d67300c20db915717c8180991d2a99a054679dee".toUpperCase());
        final byte[] SNonce = BaseEncoding.base16().decode("bd2735ca00654390ef452863d853d2d2760c36c85997af77c05ca33a272ec55c".toUpperCase());
        final byte[] PMK = BaseEncoding.base16().decode("8c36c8f2e805fea9e153ff1ed457b3c1cf87f428de5432566b77e7e91a8ab5aa".toUpperCase());

        long start = System.currentTimeMillis();
        final byte[] ptk = buildPTK(PMK, AA, SPA, ANonce, SNonce);
        final byte[] tk = Arrays.copyOfRange(ptk, 32, 48);

        /*
         * DECRYPTED PACKET 12246 FROM WIRESHARK
         */
        Security.addProvider(new BouncyCastleProvider());
        byte[] nonce = BaseEncoding.base16().decode("00448500dc39ee00000000028a".toUpperCase());

        AEADParameters params = new AEADParameters(new KeyParameter(tk), 64, nonce, new byte[]{});
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

        long duration = (System.currentTimeMillis() - start);
        System.out.println("DURATION: " + duration);

        System.out.println("DECRYPTED PACKET: " + BaseEncoding.base16().encode(outputBytes));
    }
}