#!/bin/bash

echo "SCENARIO 5"
cd Server && ./server 5555 &
sshpass -p "root" ssh -n -f root@192.168.1.200 "sh -c 'nohup /root/Documents/tesi/performance5/run.sh > /dev/null 2>&1 &'"
#sshpass -p 'root' ssh root@192.168.1.200 "cd /root/Documents/tesi/performance/Client_3 && /root/Documents/tesi/performance/Client_3/client 192.168.1.206 8883"
#echo "Waiting for kill server 3"
#pkill -2 server
#echo "Server 3 killed"
#cd ..
#sshpass -p 'root' scp root@192.168.1.200:/root/Documents/tesi/performance/Client_3/Scenario_3.csv Scenario_3
