FROM jdk8-tomcat8-maven:v0.1
VOLUME /opt/tmp
COPY ./target/docker-spring-boot-1.0.0.jar /opt/tmp/app.jar
RUN sh -c 'touch /opt/tmp/app.jar'
ENV JAVA_OPTS=""
ENTRYPOINT [ "sh", "-c", "java $JAVA_OPTS -Djava.security.egd=file:/dev/./urandom -jar /opt/tmp/app.jar" ]
