#!/usr/bin/env bash

path_n=$(dirname $0)

if  [ "`uname -s`" = "Linux" ] ;then 
    echo 'hids-go';
    ps awx|grep 'hids-go' |grep -v 'grep'|awk '{print "kill -9 "$1}'|sh;
    
    mkdir -p /home/ops/hids-go;
    rm -rf /home/ops/hids-go/*;

    
    cp -r $path_n/* /home/ops/hids-go/;
    cd /home/ops/hids-go/;
    chmod +x hids-go;
    
    #> nohup.out;
    yum update iproute -y
    nohup /home/ops/hids-go/hids-go > hids-go.log 2>&1 &
fi
