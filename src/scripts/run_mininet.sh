#!/bin/bash
echo "Iniciando Mininet com P4..."
sudo mn --custom src/p4/simple_topo.py --topo mytopo --controller remote
