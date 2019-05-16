package com.danmharris;

import com.google.gson.Gson;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;
import org.influxdb.InfluxDB;
import org.influxdb.InfluxDBFactory;
import org.influxdb.dto.Query;

public class Main {

    public static void main(String[] args) throws InterruptedException {
        final String BROKER_HOST = "tcp://broker:1883";
        final String CLIENT_ID = "InfluxDBPusher";
        final MemoryPersistence PERSISTENCE = new MemoryPersistence();

        final String INFLUX_HOST = "http://influx:8086";
        final String DB_NAME = "packets";


        System.out.println("Waiting for services to come online...");
        Thread.sleep(5000);
        System.out.println("Attempting connection...");

        InfluxDB influxDB = InfluxDBFactory.connect(INFLUX_HOST);
        influxDB.query(new Query("CREATE DATABASE " + DB_NAME));
        influxDB.setDatabase(DB_NAME);
        Gson gson = new Gson();

        try {
            MqttClient client = new MqttClient(BROKER_HOST, CLIENT_ID, PERSISTENCE);
            MqttConnectOptions options = new MqttConnectOptions();
            options.setCleanSession(true);
            client.connect(options);

            Runtime.getRuntime().addShutdownHook(new ShutdownThread(client, influxDB));

            System.out.println("Connected!");
            client.subscribe("root/packets/#", new PacketMessageListener(gson, influxDB));
        } catch (MqttException e) {
            System.err.println(e);
            System.err.println("Unable to connect to broker, will now exit!");
            System.exit(1);
        }
    }
}
