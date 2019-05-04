package uk.elliotalexander;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
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

            PrintWriter writer = new PrintWriter("output.txt", "UTF-8");

            int index = 0;
            while(handle.isOpen()){
                Packet packet = handle.getNextPacketEx();
                Packet payload2 = packet.getPayload();
                Packet payload3 = payload2.getPayload();

                if(payload3 != null){

                    StringBuilder sb = new StringBuilder();
                    for(byte b : new byte[]{payload3.getRawData()[0], payload3.getRawData()[1]}){
                        sb.append(String.format("%02X", b));
                    }

                    if(sb.toString().equalsIgnoreCase("8801") || sb.toString().equalsIgnoreCase("8802")){
                        writer.println(index + " - " + sb.toString());
                        System.out.println(index + " -  " + payload3.getRawData()[0] + payload3.getRawData()[1]);
                        index++;
                    }
                }

                dumper.dump(packet);

                writer.flush();

            }

            writer.close();
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

    private void PRF(t){

    }
}
