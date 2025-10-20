# Documentação Técnica: flow_collector.p4

Este documento detalha o funcionamento do programa P4 `flow_collector.p4`, explicando cada componente, sua finalidade, o motivo de sua implementação e como cada trecho do código contribui para o funcionamento do switch programável. O objetivo é fornecer uma visão clara sobre como o switch coleta dados de fluxo, aplica políticas de controle e interage com o controlador SDN.

---

## Objetivo Geral

O `flow_collector.p4` foi desenvolvido para:

- Extrair informações detalhadas de pacotes IPv4 (incluindo TCP e UDP).
- Gerar digests com dados de fluxo e enviá-los ao controlador SDN.
- Permitir o bloqueio dinâmico de tráfego malicioso via tabela ACL.

---

## Estrutura dos Cabeçalhos

### Definição dos Cabeçalhos

```p4
header ethernet_t { ... }
header ipv4_t { ... }
header tcp_t { ... }
header udp_t { ... }
```
- **ethernet_t**: Define os campos do cabeçalho Ethernet (endereços MAC e tipo de protocolo).
- **ipv4_t**: Define os campos do cabeçalho IPv4 (endereços IP, protocolo, TTL, etc).
- **tcp_t**: Define os campos do cabeçalho TCP (portas, sequência, flags, etc).
- **udp_t**: Define os campos do cabeçalho UDP (portas e comprimento).

*Motivo*: Permite ao switch identificar e extrair informações essenciais de cada protocolo para análise e controle.

### Estrutura de Cabeçalhos Processados

```p4
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
}
```
- Agrupa todos os cabeçalhos que podem ser extraídos de um pacote.
- Facilita o acesso e manipulação dos dados durante o processamento.

---

## Metadados e Digest

```p4
struct metadata {
    bit<32> ingress_port;
    bit<32> egress_port;
    bit<32> packet_count;
    bit<32> byte_count;
}

struct FlowDigest_t {
    ip4Addr srcAddr;
    ip4Addr dstAddr;
    bit<16> srcPort;
    bit<16> dstPort;
    bit<8>  protocol;
    bit<32> packet_count;
    bit<32> byte_count;
}
```
- **metadata**: Armazena informações auxiliares, como portas e contadores.
- **FlowDigest_t**: Estrutura enviada ao controlador, contendo dados relevantes do fluxo.

*Motivo*: Permite rastrear estatísticas e enviar informações detalhadas ao controlador para análise e tomada de decisão.

---

## Parser

```p4
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
```
- **start**: Extrai o cabeçalho Ethernet e verifica o tipo de protocolo.
- **parse_ipv4**: Se for IPv4, extrai o cabeçalho IPv4 e verifica o protocolo (TCP ou UDP).
- **parse_tcp / parse_udp**: Extrai os respectivos cabeçalhos conforme o protocolo.

*Motivo*: Garante que apenas os campos relevantes sejam extraídos, otimizando o processamento e preparando os dados para análise de fluxo.

---

## Controle de Ingress

```p4
control Ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    // Tabela de ACL para dropar tráfego malicioso
    table acl_table { ... }

    // Tabela para coletar informações de fluxo
    table flow_stats { ... }

    action collect_and_digest_flow_data() { ... }
    action _drop() { ... }
    action _nop() { ... }
```
 <!-- Documentação técnica e instruções de uso atualizadas -->

# Documentação Técnica: flow_collector.p4 e execução da simulação

Este documento contém a documentação técnica do programa P4 `flow_collector.p4` e
instruções atualizadas sobre como executar a simulação usando os utilitários Python
disponíveis no repositório (`src/mininet_setup.py`, `src/main.py`).

 

## Sumário do repositório

-`src/class/controller.py`  — Controlador principal (classe `Controller`).
- `src/mininet_setup.py`    — Classe `MininetSimulator` que inicia `controller.py` como subprocesso.
- `src/main.py`             — Runner central (modos `subprocess` e `inprocess`).
- `src/flow_collector.p4`   — Programa P4 que coleta fluxos e envia digests ao controlador.

    ---

    ## Como executar rapidamente

    1. Instale dependências:

    ```bash
    pip install -r src/requirements.txt
    ```

    2. Executar o runner principal (exemplo — subprocesso por 60s):

    ```bash
    python3 src/main.py --mode subprocess --duration 60
    ```

    3. Ou executar em modo `inprocess` (útil para injetar clientes LLM):

    ```bash
    python3 src/main.py --mode inprocess --duration 60 --provider openai --api-key YOUR_KEY
    ```

    ---

    ## Documentação técnica do `flow_collector.p4`

    O `flow_collector.p4` implementa funcionalidades de extração de cabeçalhos, coleta de
    estatísticas de fluxo e envio de digests para o controlador. Abaixo segue a documentação
    detalhada (mantida do documento original) — descreve parser, controles, tabelas e ações.

    - Objetivo geral: extrair informações de pacotes IPv4/TCP/UDP, gerar digests e permitir
      bloqueio dinâmico via ACL.

    - Estrutura dos cabeçalhos: `ethernet_t`, `ipv4_t`, `tcp_t`, `udp_t`.

    - Metadados e digest: `metadata` e `FlowDigest_t` com campos como src/dst addresses,
      src/dst ports, protocol, packet_count e byte_count.

    - Parser: extrai cabeçalhos Ethernet → IPv4 → TCP/UDP conforme o protocolo.

    - Controle de Ingress: aplica `acl_table` e `flow_stats` (tabela de estatísticas de fluxo).

    - Ações importantes:
      - `collect_and_digest_flow_data()` — preenche `FlowDigest_t`, chama `digest()` e encaminha o pacote.
      - `_drop()` — marca o pacote para descarte.
      - `_nop()` — nenhuma operação.

    - O programa é compatível com o switch BMv2 e pode ser adaptado para ambientes SDN reais.

    ---

    Se desejar, posso inserir aqui o conteúdo inteiro do arquivo `flow_collector.p4` ou gerar
    diagramas/fluxogramas para ajudar na apresentação. Deseja que eu faça isso agora?

    ---

    ## Conteúdo completo de `src/flow_collector.p4`

    ```p4
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

