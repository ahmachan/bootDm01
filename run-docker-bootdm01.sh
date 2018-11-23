#!/bin/bash

# then build up then new containers
# yml文件可以读取环境变量:eg:${PWD}
COMPOSE_YML_FILE="bootdm01.yml"

docker-compose -f ${COMPOSE_YML_FILE} up -d

sudo docker ps -a
