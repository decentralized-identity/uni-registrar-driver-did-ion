# Dockerfile for universalregistrar/driver-did-ion

FROM maven:3-jdk-11 AS build
MAINTAINER Markus Sabadello <markus@danubetech.com>

# build driver-did-ion

ADD . /opt/driver-did-ion
RUN cd /opt/driver-did-ion && mvn clean install package -P war -N -DskipTests


FROM jetty:9.4-jre11-slim
MAINTAINER Markus Sabadello <markus@danubetech.com>

# variables

ENV uniregistrar_driver_did_ion_api=http://localhost:3000/operations/

# copy from build stage

COPY --from=build --chown=jetty /opt/driver-did-ion/target/*.war /var/lib/jetty/webapps/ROOT.war

# done

EXPOSE 9080
CMD java -Djetty.http.port=9080 -Dorg.eclipse.jetty.annotations.maxWait=240 -jar /usr/local/jetty/start.jar
