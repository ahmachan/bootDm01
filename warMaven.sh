#!/bin/bash

# 命令行模式打包MAVEN项目
# 1.进入项目的workspace
# 2.执行mvn package -Dmaven.test.skip=true(跳过测试，此处会对项目下的junit测试用例进行测试，如果不通过可能造成打包失败，所以跳过测试)
# 3.打包完成后去项目target目录下即可找到war包

cur_dir=$(pwd)  #此处应为项目文件所在目录
echo $cur_dir  

if [ -d $cur_dir/target/ ];then
   rm -rf $cur_dir/target/
fi

mvn package -Dmaven.test.skip=true

if [ -d $cur_dir/target/ ];then
pwd
sleep 4s
chown -R 1000:1000 $cur_dir/target/
ls -al
fi

if [ -d $cur_dir/output/ ];then
   rm -rf $cur_dir/output/
fi
mkdir $cur_dir/output
cp -R $cur_dir/target/*.war $cur_dir/output/ROOT.war
chown -R 1000:1000 $cur_dir/output/

echo the war package had been moved to the path: $cur_dir/output/
