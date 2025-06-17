
# Tutorial Completo de P4 + BMv2 - Do Iniciante ao Avançado

## Índice

- [Introdução](#introdução)
- [1. Setup do Ambiente](#1-setup-do-ambiente)
- [2. Exemplo Básico: Switch que altera MAC](#2-exemplo-básico-switch-que-altera-mac)
- [3. Roteador IPv4 com Tabela LPM](#3-roteador-ipv4-com-tabela-lpm)
- [4. Firewall Simples com P4](#4-firewall-simples-com-p4)
- [5. QoS e Prioridade de Pacotes](#5-qos-e-prioridade-de-pacotes)
- [6. Load Balancer ECMP](#6-load-balancer-ecmp)
- [7. Tunelamento VXLAN](#7-tunelamento-vxlan)
- [8. Controlador P4Runtime em Python](#8-controlador-p4runtime-em-python)
- [9. Telemetria e Monitoramento](#9-telemetria-e-monitoramento)
- [Referências](#referências)

---

## Introdução

P4 é uma linguagem de programação para definir o comportamento de planos de dados (data planes) em switches programáveis. BMv2 (Behavioral Model version 2) é um software switch que executa programas P4, ideal para aprendizado e testes. Este tutorial guia você desde a instalação do ambiente até exemplos avançados.

---

## 1. Setup do Ambiente

### Requisitos

- Linux Mint 22 (ou Ubuntu 22.04)
- Python 3.10+
- Git
- Wireshark para análise
- Mininet para simulação de redes

### Passos para instalar tudo

Crie e execute o script `install_all.sh` com o conteúdo abaixo:

```bash
#!/bin/bash
echo "Atualizando pacotes..."
sudo apt update

echo "Instalando dependências básicas..."
sudo apt install -y git build-essential cmake libtool libgc-dev bison flex \
    libgmp-dev libboost-dev libboost-iostreams-dev libboost-graph-dev \
    python3 python3-pip python3-setuptools python3-scapy \
    tcpdump wireshark cmake pkg-config libelf-dev g++ \
    libpcap-dev automake libevent-dev

echo "Instalando P4C (compilador)..."
git clone https://github.com/p4lang/p4c.git
cd p4c
git submodule update --init --recursive
mkdir build
cd build
cmake ..
make -j$(nproc)
sudo make install
cd ../..

echo "Instalando Behavioral Model (BMv2)..."
git clone https://github.com/p4lang/behavioral-model.git
cd behavioral-model
git submodule update --init --recursive
./install_deps.sh
./autogen.sh
./configure
make -j$(nproc)
sudo make install
sudo ldconfig
cd ..

echo "Instalando Mininet..."
git clone https://github.com/mininet/mininet.git
cd mininet
sudo ./util/install.sh -a
cd ..

echo "Instalação concluída!"
````

---

## 2. Exemplo Básico: Switch que altera MAC

Arquivo `basic.p4`:

```p4
#include <core.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

parser MyParser(packet_in pkt, out ethernet_t eth_hdr) {
    state start {
        pkt.extract(eth_hdr);
        transition accept;
    }
}

control MyIngress(inout ethernet_t eth_hdr) {
    apply {
        // Se destino MAC for 11:22:33:44:55:66, troca o MAC de origem para aa:bb:cc:dd:ee:ff
        if (eth_hdr.dstAddr == 0x112233445566) {
            eth_hdr.srcAddr = 0xaabbccddeeff;
        }
    }
}

control MyDeparser(packet_out pkt, in ethernet_t eth_hdr) {
    apply {
        pkt.emit(eth_hdr);
    }
}

package SimpleSwitch(MyParser p, MyIngress ig, MyDeparser d);

SimpleSwitch() main = SimpleSwitch(MyParser(), MyIngress(), MyDeparser());
```

### Como compilar e rodar

```bash
p4c --target bmv2 --arch v1model -o basic.json basic.p4
simple_switch basic.json
```

---

## 3. Roteador IPv4 com Tabela LPM

* Utilize o `v1model` com parsing de headers Ethernet e IPv4.
* Configure tabela `ipv4_lpm` para fazer forwarding baseado no prefixo.
* Exemplo de inserção de entradas via P4Runtime.

---

## 4. Firewall Simples com P4

* Insira regras para bloquear pacotes vindos de IPs específicos.
* Utilize tabelas de controle para ações drop ou forward.
* Exemplos de regras podem ser inseridas dinamicamente via controller.

---

## 5. QoS e Prioridade de Pacotes

* Marque pacotes com diferentes valores DSCP.
* Separe filas com base em prioridade para garantir QoS.
* Controle de largura de banda em filas distintas.

---

## 6. Load Balancer ECMP

* Distribua o tráfego de saída entre múltiplos caminhos de custo igual.
* Utilize hashing de cabeçalhos para balancear conexões.
* Implemente em P4 e teste com múltiplos hosts no Mininet.

---

## 7. Tunelamento VXLAN

* Implemente encapsulamento e desencapsulamento VXLAN.
* Parseie cabeçalhos UDP, VXLAN e Ethernet.
* Use tabelas para mapear IDs de VXLAN para destinos.

---

## 8. Controlador P4Runtime em Python

Exemplo simples `controller.py`:

```python
#!/usr/bin/env python3
from p4runtime_lib.simple_controller import SimpleController

def main():
    controller = SimpleController()
    controller.connect()
    controller.write_table_entry(
        table_name="ipv4_lpm",
        match_fields={"hdr.ipv4.dstAddr": ("10.0.0.1", 32)},
        action_name="ipv4_forward",
        action_params={"dst_mac": "00:11:22:33:44:55", "port": 1}
    )
    print("Entrada inserida na tabela ipv4_lpm.")

if __name__ == "__main__":
    main()
```

* Configure o switch BMv2 com `simple_switch_grpc`.
* Conecte o controlador via gRPC para controlar as tabelas.

---

## 9. Telemetria e Monitoramento

* Colete métricas do switch usando In-Band Network Telemetry (INT).
* Exporte dados para Prometheus e visualize no Grafana.
* Monitore performance, latência e utilização.

---

## Referências

* [P4 Language Consortium](https://p4.org/)
* [P4 Tutorial GitHub](https://github.com/p4lang/tutorials)
* [BMv2 Behavioral Model](https://github.com/p4lang/behavioral-model)
* [Mininet](http://mininet.org/)
* [P4Runtime Documentation](https://p4.org/p4runtime/)

---
