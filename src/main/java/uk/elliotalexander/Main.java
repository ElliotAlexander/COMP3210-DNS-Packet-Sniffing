package uk.elliotalexander;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;

import java.net.*;
import java.util.Collections;
import java.util.Enumeration;


public class Main {

    public static void main(String[] args) {
        new Main();
    }

    public Main(){
        try {
            printInterfaces();

            System.out.println("Done printing interfaces");


            PcapNetworkInterface nif = Pcaps.getDevByName("wlan0");
            int snapLen = 65536;
            PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
            int timeout = 1000;
            System.out.println("Opening interface");
            PcapHandle handle = nif.openLive(snapLen, mode, timeout);
            System.out.println("Opened handle, awaiting packet.");

            PcapDumper dumper = handle.dumpOpen("out.pcap");


            while(handle.isOpen()){
                Packet packet = handle.getNextPacketEx();
                System.out.println(packet.getClass());
                Packet payload2 = packet.getPayload();
                System.out.println(payload2.getClass());
                Packet payload3 = payload2.getPayload();
                System.out.println(payload3.getClass());
                System.out.println(payload3);
                dumper.dump(packet);

            }

            handle.close();


        } catch (Exception e){
            System.out.println("Error - " + e.toString() + "\n ");
            e.printStackTrace();
        }

    }

    private void printInterfaces()
    {
        try {
            Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
            for (NetworkInterface netint : Collections.list(nets))
                displayInterfaceInformation(netint);
        } catch (Exception e){
            e.printStackTrace();
        }

    }


    private void displayInterfaceInformation(NetworkInterface netint) throws SocketException {
        System.out.printf("Display name: %s\n", netint.getDisplayName());
        System.out.printf("Name: %s\n", netint.getName());
        Enumeration<InetAddress> inetAddresses = netint.getInetAddresses();
        for (InetAddress inetAddress : Collections.list(inetAddresses)) {
            System.out.printf("InetAddress: %s\n", inetAddress);
        }
        System.out.printf("\n");
    }
}
