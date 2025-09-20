# Adaptação do Artigo: Detecção de Anomalias de Rede com P4, Mininet e LLM (Abordagem Simulada)

## 1. Introdução

Este documento detalha a adaptação de um artigo existente para a criação de um sistema de detecção de anomalias de rede, utilizando os conceitos de P4 (Programming Protocol-independent Packet Processors), Mininet para emulação de rede e Large Language Models (LLMs) para análise de fluxo e detecção de anomalias. Dada a complexidade de configurar um ambiente de emulação completo com P4 e Mininet em um ambiente sandboxed, a abordagem adotada é a de **simulação**. O foco principal é ilustrar a arquitetura, a lógica de coleta de dados, a análise por IA e a resposta dinâmica do sistema, sem a necessidade de uma execução em tempo real de todos os componentes de rede.

## 2. Design da Arquitetura do Sistema para Detecção de Anomalias de Rede (Abordagem Simulada)

O sistema proposto integra componentes de rede programáveis com inteligência artificial para monitorar o tráfego, identificar comportamentos anômalos e aplicar contramedidas de forma autônoma. A arquitetura é modular e compreende os seguintes elementos:

### 2.1. Ambiente de Emulação de Rede (Mininet - Simulado)

Em um cenário real, o Mininet seria empregado para emular uma topologia de rede definida por software (SDN), composta por hosts, links e switches programáveis P4. Para os propósitos desta simulação, **assumimos a existência de uma topologia Mininet** que geraria o tráfego de rede. A simulação concentra-se na geração de dados de fluxo que seriam naturalmente produzidos por tal ambiente, permitindo a validação da lógica do sistema sem a sobrecarga de uma emulação completa.

### 2.2. Switches Programáveis P4 (BMv2 - Simulado)

Os switches dentro do ambiente Mininet seriam instâncias do Behavioral Model version 2 (BMv2), que oferece suporte à programação P4. Um programa P4, denominado `flow_collector.p4`, seria carregado nesses switches para executar as seguintes funções:

- **Coleta de Dados de Fluxo**: Extração de informações cruciais dos cabeçalhos dos pacotes (como endereços IP de origem/destino, portas, protocolo e tamanho do pacote) e metadados (como tempo de chegada e contadores de pacotes/bytes).

- **Encaminhamento de Pacotes**: Execução do encaminhamento básico de pacotes conforme as regras programadas.

- **Relatório de Eventos (Digest)**: Envio dos dados de fluxo coletados para o plano de controle por meio de mensagens de digest do P4Runtime, fornecendo ao controlador informações sumarizadas sobre o tráfego.

- **Tabela de ACL**: Implementação de uma tabela de controle de acesso (ACL) para permitir que o controlador instale regras de descarte para IPs maliciosos identificados pela LLM.

Nesta simulação, **o código P4 é apresentado e sua lógica de coleta de dados e digest é explicada**, mas sua execução em um switch BMv2 físico ou emulado é abstraída. O controlador Python simula o recebimento desses digests, permitindo que a lógica de processamento seja testada independentemente da infraestrutura de rede subjacente.

### 2.3. Plano de Controle (Controlador Python)

Um controlador desenvolvido em Python atua como o componente central do sistema, orquestrando a interação entre a rede e a inteligência artificial. Suas responsabilidades incluem:

- **Gerenciamento de Switches P4 (Simulado)**: Em um ambiente real, o controlador se conectaria aos switches P4 via P4Runtime para carregar programas P4 e gerenciar tabelas de fluxo. Na simulação, ele **simula o envio de configurações e o recebimento de digests**.

- **Coleta de Dados (Simulada)**: **Simula o recebimento de digests** contendo dados de fluxo dos switches P4.

- **Interface com LLM**: Envio dos dados de fluxo pré-processados para a LLM para análise de anomalias.

- **Aplicação de Políticas (Simulada)**: Recebimento das recomendações ou novas regras da LLM e **simulação da tradução e aplicação** dessas regras nas tabelas de fluxo dos switches via P4Runtime.

### 2.4. Large Language Model (LLM - Simulado/Integrado)

A LLM é o componente de inteligência artificial encarregado da detecção de anomalias. Ela recebe os dados de fluxo do controlador e executa as seguintes tarefas:

- **Análise de Padrões**: Identificação de padrões normais e anômalos nos dados de fluxo de rede.

- **Detecção de Anomalias**: Sinalização de comportamentos anômalos (por exemplo, ataques DDoS, varreduras de porta, tráfego incomum).

- **Geração de Respostas**: Proposição de ações de mitigação ou novas regras de política de rede em um formato que o controlador possa interpretar e aplicar (por exemplo, "dropar tráfego do IP X").

Para a simulação, **a LLM é representada por uma função Python que simula a lógica de detecção de anomalias** e a geração de respostas, baseando-se em regras predefinidas ou heurísticas simples.

### 2.5. P4Runtime (Simulado)

P4Runtime é a API de controle padrão para switches P4, utilizada para a comunicação entre o controlador Python e os switches P4. Na abordagem simulada, **o controlador Python contém as chamadas P4Runtime, mas elas são tratadas como operações simuladas**, sem a necessidade de um servidor P4Runtime em execução.

## 3. Fluxo de Operação (Simulado)

O fluxo de operação do sistema simulado segue os seguintes passos:

1. **Inicialização**: O controlador Python é iniciado. Ele simula a configuração do pipeline P4 nos switches e a inicialização do mecanismo de digest.

1. **Coleta de Dados (Simulada)**: O controlador Python **simula a geração de dados de fluxo** (que em um cenário real viriam dos digests dos switches P4) em intervalos regulares.

1. **Processamento e Envio para LLM**: O controlador recebe os dados de fluxo simulados, os pré-processa (se necessário) e os envia para a função que simula a LLM.

1. **Análise de Anomalias pela LLM (Simulada)**: A função LLM analisa os dados de fluxo simulados para detectar anomalias. Se uma anomalia for encontrada (por exemplo, um IP de origem específico com alto volume de pacotes), ela gera uma resposta (por exemplo, uma nova regra para bloquear um IP de origem malicioso).

1. **Aplicação de Regras (Simulada)**: O controlador recebe a resposta da LLM, traduz a regra para o formato P4Runtime e **simula a instalação** dessa regra nas tabelas de fluxo dos switches P4 afetados (por exemplo, na `acl_table`).

1. **Mitigação/Resposta (Simulada)**: Os switches P4 simulados aplicariam a nova regra, modificando o comportamento do plano de dados para mitigar a anomalia.

## 4. Diagrama da Arquitetura

```mermaid
graph TD
    A[Mininet Environment (Simulado)] --> B(P4 Switches - BMv2 (Simulado))
    B --> C[P4 Program for Data Collection (Lógica)]
    C --> D[Flow Data (Simulado via Digests)]
    D --> E[Python Controller]
    E --> F[Large Language Model (LLM - Função Simulada)]
    F --> G[Anomaly Detection & New Rules (Simuladas)]
    G --> E
    E --> H[P4Runtime API (Chamadas Simuladas)]
    H --> B
```

## 5. Código P4 (`flow_collector.p4`)

O programa P4 abaixo descreve a lógica para coletar informações de fluxo e reportá-las ao plano de controle, além de incluir uma tabela de ACL para ações de drop.

```
#include <core.p4>
#include <v1model.p4>

// Definição dos cabeçalhos de protocolo
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> type;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    ip4Addr srcAddr;
    ip4Addr dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<6>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

// Definição do conjunto de cabeçalhos que o switch pode processar
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
}

// Metadados para o plano de controle (informações de fluxo)
struct metadata {
    bit<32> ingress_port;
    bit<32> egress_port;
    bit<32> packet_count;
    bit<32> byte_count;
}

// Estrutura para o digest (dados de fluxo a serem enviados ao controlador)
struct FlowDigest_t {
    ip4Addr srcAddr;
    ip4Addr dstAddr;
    bit<16> srcPort;
    bit<16> dstPort;
    bit<8>  protocol;
    bit<32> packet_count;
    bit<32> byte_count;
}

// Parser: Define como os pacotes são analisados e os cabeçalhos extraídos
parser Parser(packet_in pkt, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.type) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            0x06: parse_tcp;
            0x11: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}

// Ingress: Lógica de processamento de pacotes na entrada
control Ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    // Tabela de ACL para dropar tráfego malicioso
    table acl_table {
        key = {
            hdr.ipv4.srcAddr: exact;
        }
        actions = {
            _drop;
            _nop;
        }
        const default_action = _nop();
    }

    // Tabela para coletar informações de fluxo
    table flow_stats {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.tcp.srcPort: exact;
            hdr.tcp.dstPort: exact;
            hdr.ipv4.protocol: exact;
        }
        actions = {
            collect_and_digest_flow_data;
            _nop;
        }
        const default_action = _nop();
    }

    action collect_and_digest_flow_data() {
        // Preenche a estrutura FlowDigest_t com os dados do fluxo
        FlowDigest_t flow_digest;
        flow_digest.srcAddr = hdr.ipv4.srcAddr;
        flow_digest.dstAddr = hdr.ipv4.dstAddr;
        flow_digest.srcPort = hdr.tcp.srcPort;
        flow_digest.dstPort = hdr.tcp.dstPort;
        flow_digest.protocol = hdr.ipv4.protocol;
        flow_digest.packet_count = 1; // Cada pacote é um evento
        flow_digest.byte_count = standard_metadata.packet_length;

        // Envia o digest para o plano de controle
        digest(flow_digest, 1000, 100, 1000); // digest_id, max_timeout_ns, max_list_size, max_bytes_per_digest

        // Encaminha o pacote para a porta de saída (ou descarta, dependendo da política)
        standard_metadata.egress_spec = 1;
    }

    action _drop() {
        mark_to_drop();
    }

    action _nop() {
        // Nenhuma operação
    }

    apply {
        if (hdr.ipv4.isValid()) {
            acl_table.apply(); // Primeiro verifica a ACL
            flow_stats.apply(); // Depois coleta estatísticas de fluxo
        }
    }
}

// Egress: Lógica de processamento de pacotes na saída (vazio para este exemplo)
control Egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {

    }
}

// Deparser: Define como os cabeçalhos são remontados para formar o pacote de saída
control Deparser(packet_out pkt, in headers hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}

// Topologia principal do switch P4
V1Switch(Parser(), Ingress(), Egress(), Deparser()) main;
```

## 6. Código do Controlador Python (`controller.py`)

O controlador Python simula a interação com os switches P4 e a LLM, gerando dados de fluxo, enviando-os para análise e aplicando regras de mitigação.

```python
import time
import random
import socket

# Função para simular a LLM
def simulate_llm_anomaly_detection(flow_data):
    print(f"[LLM] Recebido dados de fluxo para análise: {flow_data}")
    # Lógica de detecção de anomalias simplificada
    # Se o IP de origem for 10.0.0.1 e o número de pacotes for alto (simulado aqui como > 5)
    if flow_data.get("src_ip") == "10.0.0.1" and flow_data.get("packet_count", 0) > 5:
        print("[LLM] Anomalia detectada: Tráfego do IP 10.0.0.1 é malicioso (alto volume).")
        return {"action": "drop", "src_ip": "10.0.0.1"}
    return {"action": "none"}

# Função para simular a aplicação de regras no switch P4
def simulate_p4_rule_application(table_name, match_fields, action_name, action_params={}):
    print(f"[P4Runtime Simulado] Aplicando regra na tabela \'{table_name}\':")
    print(f"  Match: {match_fields}")
    print(f"  Action: {action_name} com parâmetros {action_params}")
    print("[P4Runtime Simulado] Regra aplicada com sucesso (simulado).")

# Função principal do controlador (simulado)
def run_simulated_controller():
    print("Controlador simulado iniciado. Gerando e analisando dados de fluxo...")

    # Simular a configuração inicial do pipeline P4 (apenas para fins de log)
    print("[Controlador Simulado] Pipeline P4 configurado (simulado).")
    print("[Controlador Simulado] Digest configurado (simulado).")

    flow_id = 0
    while True:
        flow_id += 1
        # Simular coleta de dados de fluxo (que em um cenário real viria do switch via digest)
        # Gerar dados de fluxo aleatórios, com um IP \"malicioso\" ocasional
        src_ip_prefix = "10.0.0."
        dst_ip_prefix = "10.0.0."

        # Simular um IP malicioso (10.0.0.1) com mais frequência para teste
        if random.random() < 0.3: # 30% de chance de ser o IP malicioso
            src_ip = "10.0.0.1"
            packet_count = random.randint(6, 20) # Alto volume
        else:
            src_ip = src_ip_prefix + str(random.randint(2, 254))
            packet_count = random.randint(1, 5) # Volume normal

        dst_ip = dst_ip_prefix + str(random.randint(2, 254))
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 23, 53, 8080])
        protocol = random.choice([6, 17]) # TCP (6) ou UDP (17)
        byte_count = packet_count * random.randint(64, 1500)

        simulated_flow_data = {
            "flow_id": flow_id,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "packet_count": packet_count,
            "byte_count": byte_count
        }

        print(f"\n[Controlador Simulado] Gerado dados de fluxo: {simulated_flow_data}")

        # 4. Enviar dados para a LLM simulada
        llm_response = simulate_llm_anomaly_detection(simulated_flow_data)

        # 5. Processar resposta da LLM e aplicar ações (simulado)
        if llm_response["action"] == "drop":
            print(f"[Controlador Simulado] LLM recomendou DROPAR tráfego do IP: {llm_response["src_ip"]}")
            # Simular a aplicação da regra de drop na tabela ACL do P4
            simulate_p4_rule_application("acl_table", {"hdr.ipv4.srcAddr": llm_response["src_ip"]}, "_drop")

        time.sleep(2) # Simula intervalo de coleta e análise

if __name__ == "__main__":
    run_simulated_controller()
```

## 7. Código do Setup do Mininet (Simulado) (`mininet_setup.py`)

Este script foi adaptado para iniciar apenas o controlador Python simulado, abstraindo a complexidade da emulação completa do Mininet para este ambiente.

```python
import os
import time
import subprocess

# Caminho para o controlador Python
CONTROLLER_PATH = os.path.abspath("./controller.py")

def run_simulation():
    print("*** Iniciando o controlador simulado em segundo plano (sem Mininet real) ***\n")
    # Inicia o controlador Python simulado em segundo plano
    controller_process = subprocess.Popen(["python3.11", CONTROLLER_PATH])

    print("*** Controlador simulado em execução. A simulação será executada por 30 segundos. ***\n")
    try:
        # Manter o processo principal ativo por um tempo para que o controlador simulado possa rodar
        time.sleep(30)
    finally:
        print("\n*** Tempo de simulação esgotado. Terminando o controlador simulado... ***\n")
        controller_process.terminate()
        controller_process.wait()
        print("*** Controlador simulado terminado. ***\n")

if __name__ == "__main__":
    run_simulation()
```

## 8. Considerações Finais

Apesar dos desafios na configuração de um ambiente de emulação completo, esta documentação e os códigos simulados demonstram a viabilidade conceitual de integrar P4, Mininet e LLMs para detecção de anomalias de rede. A abordagem simulada permitiu focar na lógica de interação entre os componentes, desde a coleta de dados de fluxo até a análise por IA e a aplicação de políticas de segurança. Em um ambiente de produção, a transição para uma implementação real exigiria a superação dos desafios de compilação e execução das ferramentas P4 e Mininet, mas a base lógica estabelecida aqui seria diretamente aplicável.

## Referências

[1] Model Context Protocol. *Getting Started*. Disponível em: [https://modelcontextprotocol.io/docs/getting-started/intro](https://modelcontextprotocol.io/docs/getting-started/intro)
[2] P4 Language Consortium. *P4.org*. Disponível em: [https://p4.org/](https://p4.org/)
[3] Mininet. *Mininet: An Instant Virtual Network on your Laptop (or other PC)*. Disponível em: [http://mininet.org/](http://mininet.org/)