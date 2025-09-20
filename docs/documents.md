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

    apply {
        if (hdr.ipv4.isValid()) {
            acl_table.apply(); // Primeiro verifica a ACL
            flow_stats.apply(); // Depois coleta estatísticas de fluxo
        }
    }
}
```

### Tabela ACL (`acl_table`)

```p4
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
```
- Permite bloquear tráfego de IPs específicos.
- Chave: IP de origem.
- Ações: `_drop` (descarta o pacote), `_nop` (não faz nada).

*Motivo*: Implementa uma política de segurança dinâmica, permitindo ao controlador bloquear rapidamente fontes maliciosas.

### Tabela de Estatísticas de Fluxo (`flow_stats`)

```p4
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
```
- Coleta dados de cada fluxo TCP.
- Chaves: IPs de origem/destino, portas TCP, protocolo.
- Ações: `collect_and_digest_flow_data` (envia digest), `_nop` (não faz nada).

*Motivo*: Permite o monitoramento detalhado dos fluxos TCP, essencial para detecção de anomalias e análise de tráfego.

### Ações

```p4
action collect_and_digest_flow_data() {
    FlowDigest_t flow_digest;
    flow_digest.srcAddr = hdr.ipv4.srcAddr;
    flow_digest.dstAddr = hdr.ipv4.dstAddr;
    flow_digest.srcPort = hdr.tcp.srcPort;
    flow_digest.dstPort = hdr.tcp.dstPort;
    flow_digest.protocol = hdr.ipv4.protocol;
    flow_digest.packet_count = 1; // Cada pacote é um evento
    flow_digest.byte_count = standard_metadata.packet_length;

    digest(flow_digest, 1000, 100, 1000); // Envia o digest ao controlador

    standard_metadata.egress_spec = 1; // Encaminha o pacote para a porta de saída
}

action _drop() {
    mark_to_drop();
}

action _nop() {
    // Nenhuma operação
}
```
- **collect_and_digest_flow_data**: Preenche e envia o digest ao controlador, encaminha o pacote para a porta de saída.
- **_drop**: Marca o pacote para descarte.
- **_nop**: Não realiza nenhuma operação.

*Motivo*: Garante que cada evento de fluxo seja reportado ao controlador para análise e que políticas de bloqueio sejam aplicadas conforme necessário.

### Aplicação das Tabelas

```p4
apply {
    if (hdr.ipv4.isValid()) {
        acl_table.apply(); // Verifica a ACL
        flow_stats.apply(); // Coleta estatísticas de fluxo
    }
}
```
- Primeiro, verifica a ACL para decidir se o pacote deve ser bloqueado.
- Depois, coleta estatísticas do fluxo se o pacote for permitido.

*Motivo*: Prioriza a segurança antes da coleta de dados, evitando processamento desnecessário de tráfego malicioso.

---

## Controle de Egress

```p4
control Egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply { }
}
```
- Processa pacotes na saída do switch.
- Vazio neste exemplo.

*Motivo*: Não há lógica adicional de saída necessária para o caso de uso atual.

---

## Deparser

```p4
control Deparser(packet_out pkt, in headers hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}
```
- Remonta os cabeçalhos para formar o pacote de saída.
- Emite todos os cabeçalhos extraídos (Ethernet, IPv4, TCP, UDP).

*Motivo*: Garante que os pacotes sejam corretamente reconstruídos para transmissão após o processamento.

---

## Topologia Principal

```p4
V1Switch(Parser(), Ingress(), Egress(), Deparser()) main;
```
- Instancia o switch P4 principal, conectando parser, ingress, egress e deparser.

*Motivo*: Define o pipeline completo do switch, integrando todas as etapas de processamento.

---

## Observações Importantes

- O envio de digests permite que o controlador SDN monitore fluxos em tempo real e aplique políticas de segurança dinâmicas.
- A tabela ACL pode ser atualizada pelo controlador conforme novas ameaças são detectadas.
- O programa é compatível com BMv2 e pode ser adaptado para ambientes SDN reais.

