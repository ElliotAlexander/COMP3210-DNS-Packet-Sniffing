package uk.elliotalexander;

import com.google.common.io.BaseEncoding;
import org.bouncycastle.util.Arrays;
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

    private final PcapHandle handle;
    private final PcapDumper pcap_dumper;
    private final PrintWriter program_dump;
    private final Main top_level_listener;
    private final int thread_id;

    private Map<String, Connection> open_connections = new HashMap<String, Connection>();

    public PacketListenerThread(PcapHandle handle, PrintWriter program_dump, PcapDumper pcap_dumper, Main listener, int thread_id){
        this.handle = handle;
        this.program_dump = program_dump;
        this.pcap_dumper = pcap_dumper;
        this.top_level_listener = listener;
        this.thread_id = thread_id;
    }


    public static final byte[] pmk = BaseEncoding.base16().decode("8c36c8f2e805fea9e153ff1ed457b3c1cf87f428de5432566b77e7e91a8ab5aa".toUpperCase());


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
                byte a = ieee802dot11_raw_data.getRawData()[0];
                byte b = ieee802dot11_raw_data.getRawData()[1];
                if( a == 0x88 && (b == 0x02 || b == 0x01)){
                    System.out.println(index + " -  " + ieee802dot11_raw_data.getRawData()[0] + ieee802dot11_raw_data.getRawData()[1]);
                    try {
                        byte[] dest_addr = Arrays.copyOfRange(ieee802dot11.getHeader().getRawData(), 5, 10);
                        byte[] src_addr = Arrays.copyOfRange(ieee802dot11.getHeader().getRawData(), 15, 20);
                        byte[] key = Arrays.concatenate(dest_addr, src_addr);
                        byte[] packet_id = { ieee802dot11.getHeader().getRawData()[23], ieee802dot11.getHeader().getRawData()[24] };

                        if(open_connections.containsKey(key)){
                            open_connections.get(key).addEapolMessage(ieee802dot11_raw_data.getPayload().getRawData(), packet_id);
                        } else {
                            if(!(packet_id[0] == 0x00 && packet_id[1] == 0x8a)){
                                Connection c = new Connection(dest_addr, src_addr, pmk);
                                open_connections.put(packet_id.toString(), c);
                                new DecoderThread(c).run();
                            }
                        }
                    } catch (Exception e){
                        e.printStackTrace();
                    }
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
