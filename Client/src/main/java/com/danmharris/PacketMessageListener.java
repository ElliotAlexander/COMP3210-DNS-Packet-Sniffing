package com.danmharris;

import com.danmharris.json.DnsPacket;
import com.danmharris.json.GenericPacket;
import com.google.gson.Gson;
import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.IMqttMessageListener;
import org.eclipse.paho.client.mqttv3.MqttCallback;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.influxdb.InfluxDB;
import org.influxdb.dto.Point;

import java.util.concurrent.TimeUnit;

public class PacketMessageListener implements MqttCallback {
    private final Gson GSON;
    private final InfluxDB INFLUX;

    public PacketMessageListener(Gson gson, InfluxDB influx) {
        this.GSON = gson;
        this.INFLUX = influx;
    }


    @Override
    public void connectionLost(Throwable throwable) {

    }

    @Override
    public void messageArrived(String s, MqttMessage mqttMessage) {
        GenericPacket packet;
        long time = System.currentTimeMillis();

        if (s.equals("root/packets/dns")) {
            DnsPacket dnsPacket = GSON.fromJson(mqttMessage.toString(), DnsPacket.class);

            for (String question : dnsPacket.getQuestions()) {
                INFLUX.write(Point.measurement("dnsQuery")
                        .time(time, TimeUnit.MILLISECONDS)
                        .addField("question", question)
                        .build()
                );
            }

            packet = dnsPacket;
        } else {
            packet = GSON.fromJson(mqttMessage.toString(), GenericPacket.class);
        }

        INFLUX.write(Point.measurement("packet")
                .time(time, TimeUnit.MILLISECONDS)
                .addField("srcAddress", packet.getSrcAddress())
                .addField("destAddress", packet.getDestAddress())
                .addField("srcPort", packet.getSrcPort())
                .addField("destPort", packet.getDestPort())
                .addField("packetType", packet.getPacketType())
                .build()
        );
        //INFLUX.flush();
    }

    @Override
    public void deliveryComplete(IMqttDeliveryToken iMqttDeliveryToken) {

    }
}
