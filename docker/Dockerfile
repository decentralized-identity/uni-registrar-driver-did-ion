# Dockerfile for universalregistrar/driver-did-ion

FROM maven:3-openjdk-11
MAINTAINER Markus Sabadello <markus@danubetech.com>

USER root

ENV PATH $JAVA_HOME/bin:$PATH

# build driver-did-ion

ADD . /opt/driver-did-ion
RUN cd /opt/driver-did-ion && mvn clean install package -N -DskipTests

# variables

ENV uniregistrar_driver_did_sidetreeApi=http://localhost:3000/operations/

# done

EXPOSE 9080

RUN chmod a+rx /opt/driver-did-ion/docker/run-driver-did-ion.sh
CMD "/opt/driver-did-ion/docker/run-driver-did-ion.sh"
