package uk.elliotalexander;

import com.google.common.io.BaseEncoding;
import com.google.gson.Gson;
import org.bouncycastle.util.Arrays;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.Packet;
import uk.elliotalexander.exceptions.InterfaceHandleClosedException;

import java.io.EOFException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeoutException;

public class PacketListenerThread extends Thread {

    public static final byte[] pmk = BaseEncoding.base16().decode("8c36c8f2e805fea9e153ff1ed457b3c1cf87f428de5432566b77e7e91a8ab5aa".toUpperCase());

    private final PcapHandle handle;
    private final PcapDumper pcap_dumper;
    private final MqttClient mqttClient;
    private final Gson gson;
    private final Main top_level_listener;
    private final PcapDumper decrypt_dump;

    private final int DEST_ADDR_RANGE_START = 4;
    private final int DEST_ADDR_RANGE_END = 10;

    private final int SRC_ADDR_RANGE_START = 10;
    private final int SRC_ADDR_RANGE_END = 16;

    private final int PACKET_FIRST_BYTE_INDEX = 0;
    private final int PACKET_SECOND_BYTE_INDEX = 1;

    private final byte PACKET_802DOT11_IDENTIFIER = (byte) 0x88;
    private final byte PACKET_EAPOL_IDENTIFIER_TYPEA = (byte) 0x02;
    private final byte PACKET_EAPOL_IDENTIFIER_TYPEB = (byte) 0x01;

    private final int EAPOL_TYPE_IDENTIFIER_BIT1_INDEX = 39;
    private final int EAPOL_TYPE_IDENTIFIER_BIT2_INDEX = 40;
            ;

    private Map<String, Connection> open_connections = new ConcurrentHashMap<>();
    private Map<String, Long> open_connections_timestamped = new ConcurrentHashMap<>();


    public PacketListenerThread(PcapHandle handle, PcapDumper pcap_dumper, PcapDumper decyrpt_dump, MqttClient mqttClient, Gson gson, Main listener) {
        this.handle = handle;
        this.pcap_dumper = pcap_dumper;
        this.mqttClient = mqttClient;
        this.gson = gson;
        this.top_level_listener = listener;
        this.decrypt_dump = decyrpt_dump;
    }

    @Override
    public void run() {
        while (handle.isOpen()) {
            Packet radiotap_top_level_packet = null;

            try {
                // Get the next packet from the interface.
                // These are buffered, so we shouldn't miss any.
                radiotap_top_level_packet = handle.getNextPacketEx();
            } catch (PcapNativeException | TimeoutException | NotOpenException | EOFException e) {
                System.out.println("Error - failed to maintain handle.");
                handle.close();
                // Throw an exception back to main, and terminate the thread.
                top_level_listener.throwThreadException((Exception) new InterfaceHandleClosedException());
            }


            // The top level packet is wrapped in an abstract packet object. Hence:
            //
            // P1 -> Abstract packet
            // P1.getPayload() -> Radiotap packet (on wire)
            // P1.getPayload().getPayload() -> 802.11 packet.
            //

            Packet ieee802dot11 = radiotap_top_level_packet.getPayload().getPayload();
            byte[] packet_content = ieee802dot11.getRawData();

            // The first two bytes of the packet are used to identify it's type.
            byte packet_first_byte = packet_content[PACKET_FIRST_BYTE_INDEX];
            byte packet_second_byte = packet_content[PACKET_SECOND_BYTE_INDEX];

            try {
                if (packet_first_byte ==  PACKET_802DOT11_IDENTIFIER) {     // If an 802.11 packet of some description.

                    // Pull out the source and desination MAC adddresses from the packet.
                    byte[] dest_addr = Arrays.copyOfRange(ieee802dot11.getRawData(), DEST_ADDR_RANGE_START, DEST_ADDR_RANGE_END);
                    byte[] src_addr = Arrays.copyOfRange(ieee802dot11.getRawData(), SRC_ADDR_RANGE_START, SRC_ADDR_RANGE_END);

                    // Take them as strings, for use in keying the connection map.
                    String srcString = BaseEncoding.base16().encode(src_addr);
                    String destString = BaseEncoding.base16().encode(dest_addr);

                    // Sort srcString and DestString lexographically - i.e. so that packets being sent or receiver in either direction
                    // Are always indexed by the same key. Without this sort, there'd be two connection objects for the direction of the packet.
                    String key = srcString.compareTo(destString) < 0 ? srcString + destString : destString + srcString;

                    if (packet_second_byte == PACKET_EAPOL_IDENTIFIER_TYPEA || packet_second_byte == PACKET_EAPOL_IDENTIFIER_TYPEB) {     // If an EAPOL packet
                        byte[] packet_id = {
                                packet_content[EAPOL_TYPE_IDENTIFIER_BIT1_INDEX],
                                packet_content[EAPOL_TYPE_IDENTIFIER_BIT2_INDEX]
                        };

                        // If the sniffer has seen this connection before, expand it.
                        if (open_connections.containsKey(key)) {
                            Connection c = open_connections.get(key);
                            c.addEapolMessage(packet_content, packet_id);
                        } else {
                            // Else we need a new connection object.
                            System.out.println("Found EAPOL packet. Opening new connection between " + srcString + " -> " + destString);
                            Connection c = new Connection(dest_addr, src_addr, pmk);
                            c.addEapolMessage(packet_content, packet_id);
                            open_connections.put(key, c);
                            open_connections_timestamped.put(key, System.currentTimeMillis());
                        }
                    } else {        // if NOT an eapol packet
                        if (open_connections.containsKey(key)) {    // If the connection has already been identifier
                            Connection c = open_connections.get(key);       // Start decryption
                            new DecryptionThread(c, this.mqttClient, this.gson, packet_content, decrypt_dump).start();
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            // Write to PCAP file
            try {
                pcap_dumper.dump(radiotap_top_level_packet);
            } catch (NotOpenException e) {
                System.out.println("Error - failed to maintain output handle");
                pcap_dumper.close();
                top_level_listener.throwThreadException((Exception) new NotOpenException());
            }

        }
    }


    public String[] getOpenConnectionIDs(){
        return open_connections.keySet().toArray(new String[open_connections.keySet().size()]);
    }

    public long getConnectionTimestamp(String connection_id){
        return open_connections_timestamped.get(connection_id);
    }

    public Boolean pruneConnection(String connection_id){
        try {
            open_connections_timestamped.remove(connection_id);
            open_connections.remove(connection_id);
            return true;
        } catch (Exception e){
            // There's the very vague possibility that the connection might be removed while being decrypted in another thread
            return false;
        }
    }
}
