package uk.elliotalexander;

import com.google.common.io.BaseEncoding;
import com.google.common.util.concurrent.Runnables;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

public class DecoderThread implements Runnable {

    private final Connection working_connection;

    public DecoderThread(Connection c){
        this.working_connection = c;
    }


    @Override
    public void run() {
        this.working_connection.generateTk();
    }
}
