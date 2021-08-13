#include <core.p4>
#include <psa.p4>

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

struct empty_metadata_t {
}

error {
    IPv4IncorrectVersion,
    IPv4OptionsNotSupported
}

parser ingress_parser(
    packet_in packet,
    out headers_t headers,
    inout empty_metadata_t local_metadata,
    in psa_ingress_parser_input_metadata_t standard_metadata,
    in empty_metadata_t resubmit_metadata,
    in empty_metadata_t recirculate_metadata
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
        bit<4> version = headers.ipv4.version;
        verify(version == 4w4, error.IPv4IncorrectVersion);
        verify(headers.ipv4.ihl == 4w5, error.IPv4OptionsNotSupported);
        transition accept;
    }    
}

control ingress_deparser(
    packet_out packet,
    out empty_metadata_t clone_ingress_to_egress_metadata,
    out empty_metadata_t resubmit_metadata,
    out empty_metadata_t normal_metadata,
    inout headers_t headers,
    in empty_metadata_t local_metadata,
    in psa_ingress_output_metadata_t output_metadata
)
{
    apply {
        packet.emit(headers.ethernet);
        packet.emit(headers.ipv4);
    }
}

control ingress_processing(
    inout headers_t headers,
    inout empty_metadata_t local_metadata,
    in psa_ingress_input_metadata_t input_metadata,
    inout psa_ingress_output_metadata_t output_metadata
)
{
    bool dropped = false;

    action drop_action() {
        output_metadata.egress_port = (PortId_t) 4;  // TODO: Use a constant
        // mark_to_drop(standard_metadata);   TODO: Can we use this????
        dropped = true;
    }

    action to_port_action(PortId_t port) {
        headers.ipv4.ttl = headers.ipv4.ttl - 1;
        output_metadata.egress_port = port;
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

parser egress_parser(
    packet_in packet,
    out headers_t headers,
    inout empty_metadata_t local_metadata,
    in psa_egress_parser_input_metadata_t standard_metadata,
    in empty_metadata_t metadata,
    in empty_metadata_t clone_ingress_to_egress_metadata,
    in empty_metadata_t clone_egress_to_egress_metadata
)
{
    state start {
        transition accept;
    }
}

control egress_deparser(
    packet_out packet,
    out empty_metadata_t clone_egress_to_egress_metadata,
    out empty_metadata_t recirculate_metadata,
    inout headers_t headers,
    in empty_metadata_t local_metadata,
    in psa_egress_output_metadata_t psa_egress_output_metadata,
    in psa_egress_deparser_input_metadata_t psa_egress_deparser_input_metadata
)
{
    // Do nothing
    apply { }
}

control egress_processing(
    inout headers_t headers,
    inout empty_metadata_t local_metadata,
    in psa_egress_input_metadata_t psa_egress_input_metadata,
    inout psa_egress_output_metadata_t psa_egress_output_metadata
)
{
    // Do nothing
    apply { }
}

PSA_Switch(
    IngressPipeline(ingress_parser(), ingress_processing(), ingress_deparser()),
    PacketReplicationEngine(),
    EgressPipeline(egress_parser(), egress_processing(), egress_deparser()),
    BufferingQueueingEngine()
) main;
