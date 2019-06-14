# Advanced Computer Networks - Packet Sniffing

**Warning - running this code on Networks which you don't control is illegal. Capturing packets between devices you don't control is also illegal. This code is for academic purposes only.**

[![CircleCI](https://circleci.com/gh/ElliotAlexander/COMP3210-DNS-Packet-Sniffing.svg?style=svg&circle-token=64d9f47a327a6d78791c278e9c23a137ab84af39)](https://circleci.com/gh/ElliotAlexander/COMP3210-DNS-Packet-Sniffing)

This project was completed as an open-ended task for COMP3210. The aim of the project is to promiscuously capture packets from a target Wi-Fi network, aggregating packet data in a database and front end analytics client. The application is split into two parts. A local backend interfaces with a target network interface and decrypts incoming packets, provided an EAPOL handshake is captured. This backend then publishes packets to an MQTT broker, where a frontend client adds them to InfluxDB. This interfaces with a Grafana instance, allowing local visualization and analytics on incoming packets. 

In addition the the project source, two accompanying reports detailing the project are included in /docs/. The commands requried to configure a promiscuous enabled WiFi Adaptor are included in commands.txt.