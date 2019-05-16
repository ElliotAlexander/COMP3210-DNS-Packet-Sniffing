package uk.elliotalexander.json;

public class JsonGenericPacket {
    private final String srcAddress;
    private final String destAddress;
    private final int srcPort;
    private final int destPort;
    private final String packetType;

    public JsonGenericPacket(String srcAddress, String destAddress, int srcPort, int destPort, String packetType) {
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

    public int getSrcPort() {
        return srcPort;
    }

    public int getDestPort() {
        return destPort;
    }

    public String getPacketType() {
        return packetType;
    }
}
