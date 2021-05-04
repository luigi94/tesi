#!/bin/bash

cd /root/Documents/tesi/performance6/Client && /root/Documents/tesi/performance6/Client/client 192.168.1.206 1111
sshpass -p 'nettuno23' scp /root/Documents/tesi/performance6/Client/Scenario_6.csv luigi@192.168.1.206:/home/luigi/Documents/tesi/performance6
