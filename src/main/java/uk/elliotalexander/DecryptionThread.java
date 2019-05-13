package uk.elliotalexander;

import org.pcap4j.packet.IllegalRawDataException;

public class DecryptionThread extends Thread {


    private final Connection working_connection;
    private final byte[] header, packet;

    public DecryptionThread(Connection c, byte[] header, byte[] packet){
        this.working_connection = c;
        this.header = header;
        this.packet = packet;
    }

    @Override
    public void run() {
        try {
            System.out.println(this.working_connection.decrypt(header, packet));
        } catch (IllegalRawDataException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

}
