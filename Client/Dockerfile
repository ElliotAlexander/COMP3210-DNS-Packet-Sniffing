FROM maven:3-jdk-8-slim
COPY src /usr/src/app/src
COPY pom.xml /usr/src/app
WORKDIR /usr/src/app
RUN mvn -f pom.xml clean compile assembly:single

FROM openjdk:8-jre-slim
COPY --from=0 /usr/src/app/target/AdvancedNetworksClient-1.0-SNAPSHOT-jar-with-dependencies.jar /usr/lib/AdvancedNetworksClient/app.jar
WORKDIR /usr/lib/AdvancedNetworksClient
CMD ["java", "-jar", "app.jar"]