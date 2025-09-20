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
