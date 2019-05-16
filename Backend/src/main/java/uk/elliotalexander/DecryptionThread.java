package uk.elliotalexander;

import com.google.gson.Gson;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.pcap4j.packet.*;
import uk.elliotalexander.json.JsonDnsPacket;
import uk.elliotalexander.json.JsonGenericPacket;

import java.util.ArrayList;
import java.util.List;

public class DecryptionThread extends Thread {


    private final Connection working_connection;
    private final MqttClient mqttClient;
    private final Gson gson;
    private final byte[] packet;

    public DecryptionThread(Connection c, MqttClient mqttClient, Gson gson, byte[] packet) {
        this.working_connection = c;
        this.mqttClient = mqttClient;
        this.gson = gson;
        this.packet = packet;
    }

    @Override
    public void run() {
        try {
            Packet p = this.working_connection.decrypt(packet);
            if (this.mqttClient != null && p.contains(IpV4Packet.class)) {
                String jsonString = null;
                String topic = "root/packets/generic";

                IpV4Packet.IpV4Header v4PacketHeader = p.get(IpV4Packet.class).getHeader();
                final String srcAddr = v4PacketHeader.getSrcAddr().toString();
                final String destAddr = v4PacketHeader.getDstAddr().toString();

                TransportPacket.TransportHeader transportPacket = p.get(TransportPacket.class).getHeader();
                final String srcPort = transportPacket.getSrcPort().toString();
                final String destPort = transportPacket.getDstPort().toString();

                if (p.contains(DnsPacket.class)) {
                    DnsPacket.DnsHeader dnsPacketHeader = p.get(DnsPacket.class).getHeader();
                    List<String> questions = new ArrayList<>();
                    for (DnsQuestion q : dnsPacketHeader.getQuestions()) {
                        questions.add(q.getQName().toString());
                    }

                    JsonDnsPacket jsonDns = new JsonDnsPacket(srcAddr, destAddr, srcPort, destPort, "DNS", questions);
                    jsonString = this.gson.toJson(jsonDns, JsonDnsPacket.class);
                    topic = "root/packets/dns";
                } else {
                    JsonGenericPacket jsonGeneric = new JsonGenericPacket(srcAddr, destAddr, srcPort, destPort, "OTHER");
                    jsonString = this.gson.toJson(jsonGeneric, JsonGenericPacket.class);
                }

                MqttMessage message = new MqttMessage(jsonString.getBytes());
                try {
                    this.mqttClient.publish(topic, message);
                } catch (MqttException e) {
                    System.err.println("Error publishing message: " + message);
                }
            }
        } catch (IllegalRawDataException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

}