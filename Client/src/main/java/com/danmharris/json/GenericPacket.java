package com.danmharris.json;

public class GenericPacket {
    private final String srcAddress;
    private final String destAddress;
    private final String srcPort;
    private final String destPort;
    private final String packetType;

    public GenericPacket(String srcAddress, String destAddress, String srcPort, String destPort, String packetType) {
        this.srcAddress = srcAddress;
        this.destAddress = destAddress;
        this.srcPort = srcPort;
        this.destPort = destPort;
        this.packetType = packetType;
    }

    public String getSrcAddress() {
        return srcAddress;
    }

    public String getDestAddress() {
        return destAddress;
    }

    public String getSrcPort() {
        return srcPort;
    }

    public String getDestPort() {
        return destPort;
    }

    public String getPacketType() {
        return packetType;
    }
}
