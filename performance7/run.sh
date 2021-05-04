#!/bin/bash

cd /root/Documents/tesi/performance7/Client && /root/Documents/tesi/performance7/Client/client 192.168.1.206 7777
sshpass -p 'nettuno23' scp /root/Documents/tesi/performance7/Client/Scenario_7.csv luigi@192.168.1.206:/home/luigi/Documents/tesi/performance7/
sshpass -p 'nettuno23' ssh luigi@192.168.1.206 "/home/luigi/Documents/tesi/performance7/shutdown_server.sh"
