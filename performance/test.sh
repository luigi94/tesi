#!/bin/bash

mkdir Scenario_1
mkdir Scenario_2
mkdir Scenario_3

cd Server_1
echo "SCENARIO 1"
./server 8881 &
sshpass -p 'root' ssh root@192.168.1.200 "cd /root/Documents/tesi/performance/Client_1 && /root/Documents/tesi/performance/Client_1/client 192.168.1.206 8881"
echo "Waiting for kill server 1"
fuser -k 8881/tcp
echo "Server 1 killed"
cd ..
sshpass -p 'root' scp root@192.168.1.200:/root/Documents/tesi/performance/Client_1/Scenario_1.csv Scenario_1

cd Server_2
echo "SCENARIO 2"
./server 8882 &
sshpass -p 'root' ssh root@192.168.1.200 "cd /root/Documents/tesi/performance/Client_2 && /root/Documents/tesi/performance/Client_2/client 192.168.1.206 8882"
fuser -k 8882/tcp
cd ..
sshpass -p 'root' scp root@192.168.1.200:/root/Documents/tesi/performance/Client_2/Scenario_2.csv Scenario_2

cd Server_3
echo "SCENARIO 3"
./server 8883 &
sshpass -p 'root' ssh root@192.168.1.200 "cd /root/Documents/tesi/performance/Client_3 && /root/Documents/tesi/performance/Client_3/client 192.168.1.206 8883"
fuser -k 8883/tcp
cd ..
sshpass -p 'root' scp root@192.168.1.200:/root/Documents/tesi/performance/Client_3/Scenario_3.csv Scenario_3
