#include <core.p4>
#include <v1model.p4>

typedef bit<48> EthernetAddress;
typedef bit<32> IPv4Address;

header ethernet_t {
    EthernetAddress dst_addr;
    EthernetAddress src_addr;
    bit<16>         ether_type;
}

header ipv4_t {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     total_len;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     frag_offset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdr_checksum;
    IPv4Address src_addr;
    IPv4Address dst_addr;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

struct metadata_t {
}

error {
    IPv4IncorrectVersion,
    IPv4OptionsNotSupported
}

parser ipv4_parser(
    packet_in packet,
    out headers_t headers,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
)
{
    state start {
        packet.extract(headers.ethernet);
        transition select(headers.ethernet.ether_type) {
            0x0800:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(headers.ipv4);
        verify(headers.ipv4.version == 4w4, error.IPv4IncorrectVersion);
        verify(headers.ipv4.ihl == 4w5, error.IPv4OptionsNotSupported);
        transition accept;
    }    
}

control ipv4_deparser(
    packet_out packet,
    in headers_t headers
)
{
    apply {
        packet.emit(headers.ethernet);
        packet.emit(headers.ipv4);
    }
}

control verify_checksum(
    inout headers_t headers,
    inout metadata_t metadata
)
{
    // Not implemented
    apply { }
}

control compute_checksum(
    inout headers_t headers,
    inout metadata_t metadata
)
{
    // Not implemented
    apply { }
}

control ingress_processing(
    inout headers_t headers,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
)
{
    bool dropped = false;

    action drop_action() {
        mark_to_drop(standard_metadata);
        dropped = true;
    }

    action to_port_action(bit<9> port) {
        headers.ipv4.ttl = headers.ipv4.ttl - 1;
        standard_metadata.egress_spec = port;
    }

    table ipv4_match {
        key = {
            headers.ipv4.dst_addr: lpm;
        }
        actions = {
            drop_action;
            to_port_action;
        }
        size = 1024;
        default_action = drop_action;
    }

    apply {
        ipv4_match.apply();
        if (dropped) return;
    }
}

control egress_processing(
    inout headers_t headers,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
)
{
    // Do nothing
    apply { }
}

V1Switch(
    ipv4_parser(),
    verify_checksum(),
    ingress_processing(),
    egress_processing(),
    compute_checksum(),
    ipv4_deparser()
) main;