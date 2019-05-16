package uk.elliotalexander;

public class DecoderThread extends Thread {

    private final Connection working_connection;

    public DecoderThread(Connection c) {
        this.working_connection = c;
    }

    @Override
    public void run() {
        this.working_connection.generateTk();
    }
}
