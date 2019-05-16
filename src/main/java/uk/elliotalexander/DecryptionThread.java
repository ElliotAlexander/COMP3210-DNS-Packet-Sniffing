package uk.elliotalexander;

import org.pcap4j.packet.IllegalRawDataException;

public class DecryptionThread extends Thread {


    private final Connection working_connection;
    private final byte[] packet;

    public DecryptionThread(Connection c, byte[] packet) {
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
