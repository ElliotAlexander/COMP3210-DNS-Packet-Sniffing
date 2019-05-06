package uk.elliotalexander;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.Packet;
import uk.elliotalexander.exceptions.InterfaceHandleClosedException;

import java.io.EOFException;
import java.io.PrintWriter;
import java.util.concurrent.TimeoutException;

public class PacketListenerThread extends Thread {

    private final PcapHandle handle;
    private final PcapDumper pcap_dumper;
    private final PrintWriter program_dump;
    private final Main top_level_listener;
    private final int thread_id;

    public PacketListenerThread(PcapHandle handle, PrintWriter program_dump, PcapDumper pcap_dumper, Main listener, int thread_id){
        this.handle = handle;
        this.program_dump = program_dump;
        this.pcap_dumper = pcap_dumper;
        this.top_level_listener = listener;
        this.thread_id = thread_id;
    }


    @Override
    public void run() {
        int index = 0;
        while(handle.isOpen()){
            Packet radiotap_top_level_packet = null;
            try {
                radiotap_top_level_packet = handle.getNextPacketEx();
            } catch (PcapNativeException | TimeoutException | NotOpenException | EOFException e){
                System.out.println("Error - failed to maintain handle.");
                handle.close();
                top_level_listener.throwThreadException((Exception)new InterfaceHandleClosedException(), thread_id);
            }

            Packet ieee802dot11 = radiotap_top_level_packet.getPayload();
            Packet ieee802dot11_raw_data = ieee802dot11.getPayload();

            if(ieee802dot11_raw_data != null){
                StringBuilder sb = new StringBuilder();
                for(byte b : new byte[]{ieee802dot11_raw_data.getRawData()[0], ieee802dot11_raw_data.getRawData()[1]}){
                    sb.append(String.format("%02X", b));
                }

                if(sb.toString().equalsIgnoreCase("8801") || sb.toString().equalsIgnoreCase("8802")){
                    System.out.println(index + " -  " + ieee802dot11_raw_data.getRawData()[0] + ieee802dot11_raw_data.getRawData()[1]);
                    index++;
                } else {
                    index++;
                }
            }


            try {
                pcap_dumper.dump(radiotap_top_level_packet);
                program_dump.flush();
            } catch (NotOpenException e){
                System.out.println("Error - failed to maintain output handle");
                pcap_dumper.close();
                program_dump.close();
                top_level_listener.throwThreadException((Exception)new NotOpenException(), thread_id);
            }

        }
    }
}
