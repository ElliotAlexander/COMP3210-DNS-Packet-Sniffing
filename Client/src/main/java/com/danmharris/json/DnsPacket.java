package com.danmharris.json;

import java.util.List;

public class DnsPacket extends GenericPacket {
    private final List<String> questions;

    public DnsPacket(String srcAddress, String destAddress, String srcPort, String destPort, String packetType, List<String> questions) {
        super(srcAddress, destAddress, srcPort, destPort, packetType);
        this.questions = questions;
    }

    public List<String> getQuestions() {
        return this.questions;
    }
}
