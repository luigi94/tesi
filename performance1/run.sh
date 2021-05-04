#!/bin/bash

cd /root/Documents/tesi/performance1/Client && /root/Documents/tesi/performance1/Client/client 192.168.1.206 1111
sshpass -p 'nettuno23' scp /root/Documents/tesi/performance1/Client/Scenario_1.csv luigi@192.168.1.206:/home/luigi/Documents/tesi/performance1
sshpass -p 'nettuno23' ssh root@192.168.1.200 "pkill -2 server"
