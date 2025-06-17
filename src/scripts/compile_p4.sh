#!/bin/bash
echo "Compilando P4..."
p4c --target bmv2 --arch v1model src/p4/simple_switch.p4 -o build/simple_switch.json
echo "Compilação concluída."

