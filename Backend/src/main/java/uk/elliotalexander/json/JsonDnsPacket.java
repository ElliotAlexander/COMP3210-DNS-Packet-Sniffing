package uk.elliotalexander.json;

import java.util.List;

public class JsonDnsPacket extends JsonGenericPacket {
    private final List<String> questions;

    public JsonDnsPacket(String srcAddress, String destAddress, int srcPort, int destPort, String packetType, List<String> questions) {
        super(srcAddress, destAddress, srcPort, destPort, packetType);
        this.questions = questions;
    }

    public List<String> getQuestions() {
        return this.questions;
    }
}
