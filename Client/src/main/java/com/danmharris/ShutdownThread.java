package com.danmharris;

import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.influxdb.InfluxDB;

public class ShutdownThread extends Thread {
    private final MqttClient MQTT_CLIENT;
    private final InfluxDB INFLUX_DB;

    public ShutdownThread(MqttClient mqttClient, InfluxDB influxDB) {
        this.MQTT_CLIENT = mqttClient;
        this.INFLUX_DB = influxDB;
    }

    @Override
    public void run() {
        System.out.println("Shutting down...");
        try {
            MQTT_CLIENT.disconnect();
            MQTT_CLIENT.close();
        } catch (MqttException e) {
            System.err.println("Unable to close broker cleanly!");
            System.exit(1);
        }

        INFLUX_DB.close();
        System.out.println("Shutdown successfull. Bye!");
    }
}
