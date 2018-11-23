#!/bin/bash
#eg:Usage: docker run [OPTIONS] IMAGE [COMMAND] [ARG...]
docker run --name=test01 -dit -p 8098:8081 -v `pwd`/target:/opt/tmp frolvlad/alpine-oraclejdk8:slim sh

#docker run --name=test01 -p 8098:8081 -idt frolvlad/alpine-oraclejdk8:slim -v `pwd`/target:/opt/tmp /bin/sh
#java -jar /opt/tmp/bootdm01-0.0.1-SNAPSHOT.jar

