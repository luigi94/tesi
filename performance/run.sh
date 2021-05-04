#!/bin/bash

cd /root/Documents/tesi/performance/Client_4 && /root/Documents/tesi/performance/Client_4/client 192.168.1.206 8888
sshpass -p 'nettuno23' scp /root/Documents/tesi/performance/Client_4/Scenario_4.csv luigi@192.168.1.206:/home/luigi/Documents/tesi/performance/Server_4
