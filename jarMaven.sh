#!/bin/bash
cur_dir=$(pwd)  #此处应为项目文件所在目录
echo $cur_dir  

if [ -d $cur_dir/target/ ];then
   rm -rf $cur_dir/target/*
fi

mvn clean package -Dmaven.test.skip=true
#mvn clean install -Dmaven.test.skip=true

if [ -d $cur_dir/target/ ];then
pwd
sleep 4s
chown -R 1000:1000 $cur_dir/target/
ls -al
fi
