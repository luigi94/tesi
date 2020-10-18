#!/bin/bash

mkdir Scenario_3

cd Server_3
echo "SCENARIO 3"
./server 8883 &
sshpass -p 'root' ssh root@192.168.1.200 "cd /root/Documents/tesi/performance/Client_3 && /root/Documents/tesi/performance/Client_3/client 192.168.1.206 8883"
echo "Waiting for kill server 3"
fuser -k 8883/tcp
echo "Server 3 killed"
cd ..
sshpass -p 'root' scp root@192.168.1.200:/root/Documents/tesi/performance/Client_3/Scenario_3.csv Scenario_3
