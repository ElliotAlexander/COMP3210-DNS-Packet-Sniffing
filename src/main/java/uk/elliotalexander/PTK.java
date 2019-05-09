package uk.elliotalexander;

import com.google.common.io.BaseEncoding;
import com.google.common.primitives.UnsignedBytes;
import org.bouncycastle.util.Arrays;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsQuestion;
import org.pcap4j.packet.Packet;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

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
        final byte[] EAPOL1 = BaseEncoding.base16().decode("00002000ae4000a0200800a02008000010027109a000dc00640000000000000188023a01448500dc39eee4956e4400e6e4956e4400e600000700aaaa03000000888e0203005f02008a00100000000000000001cbc4f0a9f9879a00ef6317c7d67300c20db915717c8180991d2a99a054679dee0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b4261a22".toUpperCase());
        final byte[] EAPOL2 = BaseEncoding.base16().decode("00002000ae4000a0200800a02008000010027109a000de00640000000000000188013a01e4956e4400e6448500dc39eee4956e4400e600000700aaaa03000000888e0103007502010a00000000000000000001bd2735ca00654390ef452863d853d2d2760c36c85997af77c05ca33a272ec55c00000000000000000000000000000000000000000000000000000000000000005ef597651ffbab7c38d302f3aa9abefe001630140100000fac040100000fac040100000fac020000c03578e7".toUpperCase());
        final byte[] PMK = BaseEncoding.base16().decode("8c36c8f2e805fea9e153ff1ed457b3c1cf87f428de5432566b77e7e91a8ab5aa".toUpperCase());


        byte[] packet_id_1 = { EAPOL1[70], EAPOL1[71] };
        byte[] packet_id_2 = { EAPOL2[70], EAPOL2[71] };
        long start = System.currentTimeMillis();
        Connection connection = new Connection(SPA, AA, PMK);
        connection.addEapolMessage(EAPOL1, packet_id_1);
        connection.addEapolMessage(EAPOL2, packet_id_2);
        connection.generateTk();

        /*
         * DECRYPTED PACKET 12246 FROM WIRESHARK
         */
        final String header = "88413000e4956e4400e6448500dc39eee4956e4400e6402800008a02002000000000";
        final byte[] headerBytes = BaseEncoding.base16().decode(header.toUpperCase());
        final String encrypted = "39f7b6a6ec785448b1d28f563e62b7d53b571038ba9d83d11a2a3aa4ea226094b6b4a41b2bf400b3f0534ebfc76b93f96857e5a3e255f112870986453aca5cba0332a8a21e0317177c3d21117e72a8982409f92853c436e15eb48d";
        byte[] encryptedBytes = BaseEncoding.base16().decode(encrypted.toUpperCase());

        Packet test = connection.decrypt(headerBytes, encryptedBytes);
        DnsPacket dns = test.getPayload().getPayload().get(DnsPacket.class);

        long duration = (System.currentTimeMillis() - start);
        System.out.println("DURATION: " + duration);
        
        for (DnsQuestion q : dns.getHeader().getQuestions()) {
            System.out.println(q.getQName());
        }


    }
}