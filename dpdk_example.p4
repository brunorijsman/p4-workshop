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

struct metadata_t {
}

error {
    IPv4IncorrectVersion,
    IPv4OptionsNotSupported
}

parser ipv4_parser(packet_in packet,
                   out headers_t hd,
                   inout metadata_t meta,
                   inout standard_metadata_t standard_meta)
{
    state start {
        packet.extract(hd.ethernet);
        transition select(hd.ethernet.ether_type) {
            0x0800:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hd.ipv4);
        verify(hd.ipv4.version == 4w4, error.IPv4IncorrectVersion);
        verify(hd.ipv4.ihl == 4w5, error.IPv4OptionsNotSupported);
        transition accept;
    }    
}

control ipv4_deparser(packet_out packet,
                      in headers_t hdr)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

control ingress(inout headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata)
{
    bool dropped = false;

    action drop_action() {
        mark_to_drop(standard_metadata);
        dropped = true;
    }

    action to_port_action(bit<9> port) {
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        standard_metadata.egress_spec = port;
    }

    table ipv4_match {
        key = {
            hdr.ipv4.dst_addr: lpm;
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

control egress(inout headers_t hdr,
               inout metadata_t meta,
               inout standard_metadata_t standard_metadata)
{
    apply { }
}

PSA_Switch(IngressPipeline(ipv4_parser, ingress, ipv4_deparser),
           PacketReplicationEngine(),
           IngressPipeline(ipv4_parser, egress, ipv4_deparser),
           BufferingQueueingEngine()) main;
