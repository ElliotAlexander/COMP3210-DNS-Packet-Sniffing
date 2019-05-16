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

    String interface_name = "wlan0";
    String handle_dump_name = "out.pcap";
    String program_dump_name = "output.txt";


    private int thread_id = 0;
    private HashMap<Integer, PacketListenerThread> threads = new HashMap<Integer, PacketListenerThread>();


    public static void main(String[] args) {
        new Main();
    }

    public Main() {
        Utils.printInterfaces();

        PcapHandle handle = null;
        PcapDumper dumper = null;
        PrintWriter writer = null;

        try {
            handle = openInterfaces(this.interface_name);
            dumper = handle.dumpOpen(this.handle_dump_name);
            writer = new PrintWriter(this.program_dump_name, "UTF-8");
        } catch (Exception e) {
            System.out.println("Error - " + e.toString() + "\n ");
            e.printStackTrace();
        }

        final String MQTT_BROKER = "tcp://localhost:1883";
        final String MQTT_CLIENT_ID = "PacketCapture";
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

        Gson gson = new Gson();

        PacketListenerThread thread = new PacketListenerThread(handle, writer, dumper, mqtt, gson, this, thread_id);
        threads.put(thread_id, thread);
        thread_id++;
        thread.start();
    }

    public void throwThreadException(Exception e, int thread_id) {
        threads.get(thread_id).interrupt();
        System.out.println("Killed thread " + thread_id);
        e.printStackTrace();
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
}