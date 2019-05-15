package uk.elliotalexander;

import com.google.common.io.BaseEncoding;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;

public class DecryptionThread extends Thread {


    private final Connection working_connection;
    private final byte[] packet;

    public DecryptionThread(Connection c, byte[] packet){
        this.working_connection = c;
        this.packet = packet;
    }

    @Override
    public void run() {
        try {
            System.out.println(this.working_connection.decrypt(packet));
        } catch (IllegalRawDataException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

}
