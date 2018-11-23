#!/bin/bash

TARGET_JAR_PACK="target/xmage-spring-boot-demo-1.0-SNAPSHOT.jar"

/bin/bash -c "java $JAVA_OPTS -Djava.security.egd=file:/dev/./urandom -jar $TARGET_JAR_PACK" 

#java -jar $TARGET_JAR_PACK
