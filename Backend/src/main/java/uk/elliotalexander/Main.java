package uk.elliotalexander;

import com.google.gson.Gson;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;
import org.pcap4j.core.*;
import uk.elliotalexander.exceptions.InterfaceNotFoundException;

import java.io.PrintWriter;
import java.util.HashMap;


public class Main {

    private final String interface_name = "wlan0";                      // The intercace to be used - must be open. The Alfa chip we have always uses wlan0 (not wlan0mon)
    private final String handle_dump_name = "out.pcap";                 // The 'encrypted' output file, all packets captured in air.
    private final String decrypt_dumper_name = "decrypted.pcap";        // The 'decrypted' output file, all packets successfully decrypted.

    private final String MQTT_BROKER = "tcp://localhost:1883";          // Client access address for MQTT
    private final String MQTT_CLIENT_ID = "PacketCapture";

    private PcapHandle handle;                                          // Handle on interface interface_name, wrapper for packet capture.
    private PcapDumper dumper;                                          // Output dumper for all packets, wrapper on a pcap file.
    private PcapDumper decrypt_dumper;                                  // Output dumper for decrypted packets, wrapper on a pcap file

    private final PacketListenerThread thread;                          // The second 'main' thread, which handles all the packet capture.
                                                                        // This will operate in parallel to main, which handles pruning and exceptions.

    public static void main(String[] args) {
        new Main();
    }

    public Main() {
        Utils.printInterfaces();
        openPcapInterfaces();
        Gson gson = new Gson();
        MqttClient mqtt = openMqttClient(MQTT_BROKER, MQTT_CLIENT_ID);

        this.thread = new PacketListenerThread(handle, dumper, decrypt_dumper, mqtt, gson, this);
        this.thread.start();

        try {
            pruneOpenConnections(thread);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }


    public void throwThreadException(Exception e) {
        thread.interrupt();
        System.out.println("Killed Packet listener thread!");
        e.printStackTrace();
    }


    public MqttClient openMqttClient(String MQTT_BROKER, String MQTT_CLIENT_ID){
        final MemoryPersistence PERSISTENCE = new MemoryPersistence();
        MqttClient mqtt = null;
        try {
            mqtt = new MqttClient(MQTT_BROKER, MQTT_CLIENT_ID, PERSISTENCE);
            MqttConnectOptions options = new MqttConnectOptions();
            options.setCleanSession(true);
            mqtt.connect(options);
        } catch (MqttException e) {
            System.err.println("Unable to connect to MQTT broker, will not be used");
            mqtt = null;
        }
        return mqtt;
    }

    private PcapHandle openInterfaces(String interface_name) throws InterfaceNotFoundException {
        int snapLen = 65536;
        int timeout = 1000;

        try {
            PcapNetworkInterface nif = Pcaps.getDevByName(interface_name);
            PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
            System.out.println("Opening interface " + interface_name);
            PcapHandle handle = nif.openLive(snapLen, mode, timeout);
            System.out.println("Successfully opened interface on " + interface_name);
            return handle;
        } catch (PcapNativeException e) {
            throw new InterfaceNotFoundException();
        }
    }

    private void openPcapInterfaces(){
        try {
            handle = openInterfaces(this.interface_name);
            dumper = handle.dumpOpen(this.handle_dump_name);
            decrypt_dumper = handle.dumpOpen(this.decrypt_dumper_name);
        } catch (Exception e) {
            System.out.println("Error - " + e.toString() + "\n ");
            e.printStackTrace();
        }
    }

    private void pruneOpenConnections(PacketListenerThread thread) throws InterruptedException {
        while(true){
            Long current_sys_time = System.currentTimeMillis();
            for(String c : thread.getOpenConnectionIDs()){
                if(current_sys_time - thread.getConnectionTimestamp(c) > 20000){
                    System.out.println("Kicking connection!");
                    thread.pruneConnection(c);
                }
            }
            Thread.sleep(1000 - (System.currentTimeMillis() - current_sys_time));
        }
    }
}
