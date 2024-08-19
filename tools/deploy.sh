#!/usr/bin/env bash

path_n=$(dirname $0)

if  [ "`uname -s`" = "Linux" ] ;then 
    echo 'hidsgo';
    ps awx|grep 'hidsgo' |grep -v 'grep'|awk '{print "kill -9 "$1}'|sh;
    
    mkdir -p /home/ops/hidsgo;
    rm -rf /home/ops/hidsgo/*;

    
    cp -r $path_n/* /home/ops/hidsgo/;
    cd /home/ops/hidsgo/;
    chmod +x hidsgo;
    
    #> nohup.out;
    yum update iproute -y
    nohup /home/ops/hidsgo/hidsgo > hidsgo.log 2>&1 &
fi
