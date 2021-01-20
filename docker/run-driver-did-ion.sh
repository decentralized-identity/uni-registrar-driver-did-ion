#!/bin/sh

cd /opt/driver-did-ion/
mvn jetty:run -P war -Dorg.eclipse.jetty.annotations.maxWait=240
