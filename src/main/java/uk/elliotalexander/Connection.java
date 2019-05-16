package uk.elliotalexander;

import com.google.common.io.BaseEncoding;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.LlcPacket;
import org.pcap4j.packet.Packet;
import uk.elliotalexander.exceptions.UnknownEAPOLTypeException;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Represents a wireless connection between two devices
 * <p>
 * Constructed with the EAPOL handshake and address information so that TK can be derived. Then provides method for
 * decrypting future packets
 */
public class Connection {
    private final byte[] stationAddress;
    private final byte[] apAddress;
    private final byte[] pmk;
    private final byte[][] eapolMessages = new byte[4][];
    private int eapolSize = 0;
    private byte[] tk;

    /**
     * Create a new connection
     *
     * @param stationAddress Hardware address of the supplicant
     * @param apAddress      Hardware address of the access point
     * @param pmk            PMK of the network SSID and password
     */
    public Connection(byte[] stationAddress, byte[] apAddress, byte[] pmk) {
        this.stationAddress = stationAddress;
        this.apAddress = apAddress;
        this.pmk = pmk;
    }

    /**
     * Adds a new EAPOL message when it is captured
     *
     * @param message   The payload of the eapol packet.
     * @param packet_id The bytes representing the type of the eapol packet
     */
    public void addEapolMessage(byte[] message, byte[] packet_id) throws UnknownEAPOLTypeException {
        int packet_type = -1;
        if (packet_id[0] == (byte) 0x00 && packet_id[1] == (byte) 0x8a) {
            packet_type = 0;
        } else if (packet_id[0] == (byte) 0x01 && packet_id[1] == (byte) 0x0a) {
            packet_type = 1;
        } else if (packet_id[0] == (byte) 0x13 && packet_id[1] == (byte) 0xca) {
            packet_type = 2;
        } else if (packet_id[0] == (byte) 0x03 && packet_id[1] == (byte) 0x0a) {
            packet_type = 3;
        } else {
            System.out.println("Failed to find EAPOL message with hex string: " + BaseEncoding.base16().encode(packet_id));
            throw new UnknownEAPOLTypeException();
        }
        this.eapolMessages[packet_type] = message;
        this.eapolSize++;
        System.out.println("Adding EAPOL Message " + receivedEapolCount() + " / 4.");

        if (receivedAllEapol()) {
            new DecoderThread(this).start();
        }
    }

    public boolean receivedAllEapol() {
        return this.eapolSize == 4;
    }


    public int receivedEapolCount() {
        return this.eapolSize;
    }

    /**
     * Generates the Temporal Key for the connection (required to use decrypt)
     */
    public void generateTk() {
        byte[] ANonce = Arrays.copyOfRange(this.eapolMessages[0], 51, 83);
        byte[] SNonce = Arrays.copyOfRange(this.eapolMessages[1], 51, 83);

        try {
            final byte[] ptk = PTK.buildPTK(pmk, this.apAddress, this.stationAddress, ANonce, SNonce);
            this.tk = Arrays.copyOfRange(ptk, 32, 48);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    /**
     * Decrypt a wireless packet
     *
     * @param packet The raw packet to decrypt
     * @return The decrypted packet in Pcap form
     * @throws IllegalRawDataException Thrown if the packet is not of the correct form
     * @throws IllegalStateException   Thrown if the TK has not been generated yet
     */
    public Packet decrypt(byte[] packet) throws IllegalRawDataException, InterruptedException {
        if (this.tk == null) {
            return null;
        }

        byte[] pn = new byte[6];
        for (int i = 0; i < 3; i++) {
            pn[i] = 0;
            pn[i + 3] = packet[28 - i];
        }
        byte[] nonce = Arrays.concatenate(new byte[]{0}, Arrays.copyOfRange(packet, 10, 16), pn);

        AEADParameters params = new AEADParameters(new KeyParameter(this.tk), 64, nonce, new byte[]{});
        CCMBlockCipher c = new CCMBlockCipher(new AESEngine());
        c.init(false, params);

        byte[] payload = Arrays.copyOfRange(packet, 34, packet.length-4);
        byte[] outputBytes = new byte[c.getOutputSize(payload.length)];
        int result = c.processBytes(payload, 0, payload.length, outputBytes, 0);
        try {
            c.doFinal(outputBytes, result);
        } catch (Exception e) {

        }

        return LlcPacket.newPacket(outputBytes, 0, outputBytes.length);
    }
}
