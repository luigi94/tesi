#!/bin/bash

cd /root/Documents/tesi/performance5/Client && /root/Documents/tesi/performance5/Client/client 192.168.1.206 5555
sshpass -p 'nettuno23' scp /root/Documents/tesi/performance5/Client/Scenario_5.csv luigi@192.168.1.206:/home/luigi/Documents/tesi/performance5/
