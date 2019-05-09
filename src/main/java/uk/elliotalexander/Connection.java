package uk.elliotalexander;

import com.google.common.io.BaseEncoding;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.LlcPacket;
import org.pcap4j.packet.Packet;
import uk.elliotalexander.exceptions.UnknownEAPOLTypeException;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

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
    private final List<byte[]> eapolMessages = new ArrayList<byte[]>();
    private byte[] tk;
    private byte[] nonce;

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
     * @param message The raw EAPOL packet
     * @param packet_id  The bytes representing the type of the eapol packet
     */
    public void addEapolMessage(byte[] message, byte[] packet_id) throws UnknownEAPOLTypeException{
        int packet_type = -1;
       if(packet_id[0] == 0x00 && packet_id[1] == 0x8a) {
            packet_type = 1;
       } else if (packet_id[0] == 0x01 && packet_id[1] == 0x0a){
           packet_type = 2;
       } else if(packet_id[0] == 0x13 && packet_id[1] == 0xca){
            packet_type = 3;
       } else if (packet_id[0] == 0x03 && packet_id[1] == 0x0a){
            packet_type = 4;
       } else {
           throw new UnknownEAPOLTypeException();
       }

        this.eapolMessages.add(packet_type, message);
    }

    private byte[] getTk() {
        if (tk == null) {
            throw new IllegalStateException("TK has not been generated");
        }

        return this.tk;
    }

    private byte[] getNonce() {
        // Increment after return
        /*if (nonce == null) {
            throw new IllegalStateException("Nonce not initialised");
        }

        return this.nonce;*/

        return BaseEncoding.base16().decode("00448500dc39ee00000000028a".toUpperCase());
    }

    /**
     * Generates the Temporal Key for the connection (required to use decrypt)
     */
    public void generateTk() {
        byte[] ANonce = Arrays.copyOfRange(this.eapolMessages.get(0), 83, 115);
        byte[] SNonce = Arrays.copyOfRange(this.eapolMessages.get(1), 83, 115);

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
    public Packet decrypt(byte[] packet) throws IllegalRawDataException {
        AEADParameters params = new AEADParameters(new KeyParameter(this.getTk()), 64, this.getNonce(), new byte[]{});
        CCMBlockCipher c = new CCMBlockCipher(new AESEngine());
        c.init(false, params);

        byte[] outputBytes = new byte[c.getOutputSize(packet.length)];
        int result = c.processBytes(packet, 0, packet.length, outputBytes, 0);
        try {
            c.doFinal(outputBytes, result);
        } catch (Exception e) {

        }

        return LlcPacket.newPacket(outputBytes, 0, outputBytes.length);
    }
}
