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
import java.util.concurrent.TimeoutException;

public class PacketListenerThread extends Thread {

    public static final byte[] pmk = BaseEncoding.base16().decode("8c36c8f2e805fea9e153ff1ed457b3c1cf87f428de5432566b77e7e91a8ab5aa".toUpperCase());
    private final PcapHandle handle;
    private final PcapDumper pcap_dumper;
    private final PrintWriter program_dump;
    private final MqttClient mqttClient;
    private final Gson gson;
    private final Main top_level_listener;
    private final int thread_id;
    private Map<String, Connection> open_connections = new HashMap<>();


    public PacketListenerThread(PcapHandle handle, PrintWriter program_dump, PcapDumper pcap_dumper, MqttClient mqttClient, Gson gson, Main listener, int thread_id) {
        this.handle = handle;
        this.program_dump = program_dump;
        this.pcap_dumper = pcap_dumper;
        this.mqttClient = mqttClient;
        this.gson = gson;
        this.top_level_listener = listener;
        this.thread_id = thread_id;
    }

    @Override
    public void run() {
        while (handle.isOpen()) {
            Packet radiotap_top_level_packet = null;

            try {
                radiotap_top_level_packet = handle.getNextPacketEx();
            } catch (PcapNativeException | TimeoutException | NotOpenException | EOFException e) {
                System.out.println("Error - failed to maintain handle.");
                handle.close();
                top_level_listener.throwThreadException((Exception) new InterfaceHandleClosedException(), thread_id);
            }

            Packet ieee802dot11 = radiotap_top_level_packet.getPayload().getPayload();
            byte[] packet_content = ieee802dot11.getRawData();
            byte a = packet_content[0];
            byte b = packet_content[1];

            if (ieee802dot11.getRawData().length == 0) {
                continue;
            }

            try {
                if (a == (byte) 0x88) {
                    byte[] dest_addr = Arrays.copyOfRange(ieee802dot11.getRawData(), 4, 10);
                    byte[] src_addr = Arrays.copyOfRange(ieee802dot11.getRawData(), 10, 16);
                    String srcString = BaseEncoding.base16().encode(src_addr);
                    String destString = BaseEncoding.base16().encode(dest_addr);
                    String key = srcString.compareTo(destString) < 0 ? srcString + destString : destString + srcString;

                    if (b == (byte) 0x02 || b == (byte) 0x01) {

                        byte[] packet_id = {packet_content[39], packet_content[40]};

                        System.out.println("EAPOL with key: " + key);
                        if (open_connections.containsKey(key)) {
                            Connection c = open_connections.get(key);
                            c.addEapolMessage(packet_content, packet_id);
                        } else {
                            System.out.println("Found EAPOL packet. Opening new connection between " + BaseEncoding.base16().encode(src_addr) + " -> " + BaseEncoding.base16().encode(dest_addr));
                            Connection c = new Connection(dest_addr, src_addr, pmk);
                            open_connections.put(key, c);
                            c.addEapolMessage(packet_content, packet_id);
                        }
                    } else {
                        System.out.println("Found 802.11 packet.");
                        if (open_connections.containsKey(key)) {
                            System.out.println("Found open connection for " + key);
                            Connection c = open_connections.get(key);
                            new DecryptionThread(c, this.mqttClient, this.gson, packet_content).start();
                        } else {
                        }
                    }
                } else {

                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            // Write to PCAP file
            try {
                pcap_dumper.dump(radiotap_top_level_packet);
                program_dump.flush();
            } catch (NotOpenException e) {
                System.out.println("Error - failed to maintain output handle");
                pcap_dumper.close();
                program_dump.close();
                top_level_listener.throwThreadException((Exception) new NotOpenException(), thread_id);
            }

        }
    }
}
