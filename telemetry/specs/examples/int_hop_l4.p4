#include <core.p4>
#include <psa.p4>

/********************************************************************
 * headers and structs
 *******************************************************************/

/* INT shim header for TCP/UDP */
header intl4_shim_t {
    bit<8>  int_type;
    bit<8>  rsvd1;
    bit<8>  len;
    bit<6>  dscp;
    bit<2>  rsvd2;
}

/* INT header */
/* 16 instruction bits are defined in four 4b fields to allow concurrent
   lookups of the bits without listing 2^16 combinations */
header int_header_t {
    bit<4>  ver;
    bit<2>  rep;
    bit<1>  c;
    bit<1>  e;
    bit<1>  m;
    bit<7>  rsvd1;
    bit<3>  rsvd2;
    bit<5>  hop_metadata_len;
    bit<8>  remaining_hop_cnt;
    bit<4>  instruction_mask_0003;
    bit<4>  instruction_mask_0407;
    bit<4>  instruction_mask_0811;
    bit<4>  instruction_mask_1215;
    bit<16> rsvd3;
}

/* INT meta-value headers - different header for each value type */
header int_switch_id_t {
    bit<32> switch_id;
}

header int_level1_port_ids_t {
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
}

header int_hop_latency_t {
    bit<32> hop_latency;
}

header int_q_occupancy_t {
    bit<8>  q_id;
    bit<24> q_occupancy;
}

header int_ingress_tstamp_t {
    bit<32> ingress_tstamp;
}

header int_egress_tstamp_t {
    bit<32> egress_tstamp;
}

header int_level2_port_ids_t {
    bit<32> ingress_port_id;
    bit<32> egress_port_id;
}

header int_egress_port_tx_util_t {
    bit<32> egress_port_tx_util;
}

/* standard ethernet/ip/tcp headers */
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

/* define diffserv field as DSCP(6b) + ECN(2b) */
header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<6>  dscp;
    bit<2>  ecn;

    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
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

struct headers {
    ethernet_t                  ethernet;
    ipv4_t                      ipv4;
    tcp_t                       tcp;
    udp_t                       udp;
    intl4_shim_t                intl4_shim;
    int_header_t                int_header;
    int_switch_id_t             int_switch_id;
    int_level1_port_ids_t       int_level1_port_ids;
    int_hop_latency_t           int_hop_latency;
    int_q_occupancy_t           int_q_occupancy;
    int_ingress_tstamp_t        int_ingress_tstamp;
    int_egress_tstamp_t         int_egress_tstamp;
    int_level2_port_ids_t       int_level2_port_ids;
    int_egress_port_tx_util_t   int_egress_port_tx_util;
}

struct empty_metadata_t {
}

/* port id and timestamp types are defined in PSA */
struct bridged_ingress_input_metadata_t {
    PortId_t    ingress_port;
    Timestamp_t ingress_timestamp;
}

/* switch internal variables for INT logic implementation */
struct int_metadata_t {
    bit<16>  insert_byte_cnt;
    bit<8>   int_hdr_word_len;
    bit<32>  switch_id;
}

struct fwd_metadata_t {
    bit<16>  l3_mtu;
    bit<16>  checksum_state;
}

struct metadata {
    bridged_ingress_input_metadata_t bridged_istd;
    int_metadata_t                   int_metadata;
    fwd_metadata_t                   fwd_metadata;
}

error {
    BadIPv4HeaderChecksum
}

/********************************************************************
 * parsers and deparsers
 *******************************************************************/

/* Checksum verification and update of ipv4, tcp and udp are inspired by
 * p4lang/p4-spec/blob/master/p4-16/psa/examples/psa-example-incremental-checksum2.p4
 * For checksum related details, check the notes in the PSA example.
 */

/* This reference code processes INT Transit at egress where all
 * switch metadata become available.
 * Ingress doesn't need to parse or deparse INT.
 */

parser IngressParserImpl(packet_in packet,
                         out headers hdr,
                         inout metadata meta,
                         in psa_ingress_parser_input_metadata_t istd,
                         in empty_metadata_t resubmit_meta,
                         in empty_metadata_t recirculate_meta)
{
    InternetChecksum() ck;

    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);

        ck.clear();
        ck.add({
                hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.dscp, hdr.ipv4.ecn,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags, hdr.ipv4.fragOffset,
                hdr.ipv4.ttl, hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            });
        verify(hdr.ipv4.hdrChecksum == ck.get(), error.BadIPv4HeaderChecksum);

        // For incremental update of TCP/UDP checksums
        // subtract out the contributions of the IPv4 'pseudo header'
        // fields that the P4 program might change
        ck.clear();
        ck.subtract({
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                hdr.ipv4.totalLen
            });

        transition select(hdr.ipv4.protocol) {
            6 : parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        ck.subtract({
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNo,
                hdr.tcp.ackNo,
                hdr.tcp.dataOffset, hdr.tcp.res,
                hdr.tcp.flags,
                hdr.tcp.window,
                hdr.tcp.checksum,
                hdr.tcp.urgentPtr
            });
        meta.fwd_metadata.checksum_state = ck.get_state();
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        ck.subtract({
                hdr.udp.srcPort,
                hdr.udp.dstPort,
                hdr.udp.length_,
                hdr.udp.checksum
            });
        meta.fwd_metadata.checksum_state = ck.get_state();
        transition accept;
    }
}

control IngressDeparserImpl(packet_out packet,
    out empty_metadata_t clone_i2e_meta,
    out empty_metadata_t resubmit_meta,
                            out metadata normal_meta,
                            inout headers hdr,
                            in metadata meta,
                            in psa_ingress_output_metadata_t istd)
{
    apply {
        if (psa_normal(istd)) {
            normal_meta = meta;
        }
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/* indicate INT at LSB of DSCP */
const bit<6> DSCP_INT = 0x17;

parser EgressParserImpl(packet_in packet,
                        out headers hdr,
                        inout metadata meta,
                        in psa_egress_parser_input_metadata_t istd,
                        in metadata normal_meta,
                        in empty_metadata_t clone_i2e_meta,
                        in empty_metadata_t clone_e2e_meta)
{
    InternetChecksum() ck;

    state start {
        transition copy_normal_meta;
    }
    state copy_normal_meta {
        meta = normal_meta;
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6 : parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.ipv4.dscp) {
	    /* &&& is a mask operator in p4_16 */
            DSCP_INT &&& DSCP_INT: parse_intl4_shim;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.ipv4.dscp) {
            DSCP_INT &&& DSCP_INT: parse_intl4_shim;
            default: accept;
        }
    }

    /* INT headers are parsed first time at egress,
     * hence subtract INT header fields from checksum
     * for incremental update
     */
    state parse_intl4_shim {
        packet.extract(hdr.intl4_shim);
        ck.subtract({
                hdr.intl4_shim.int_type, hdr.intl4_shim.rsvd1,
                hdr.intl4_shim.len, hdr.intl4_shim.dscp, hdr.intl4_shim.rsvd2
            });
        transition parse_int_header;
    }
    state parse_int_header {
        packet.extract(hdr.int_header);
        ck.subtract({
            hdr.int_header.ver, hdr.int_header.rep,
            hdr.int_header.c, hdr.int_header.e,
            hdr.int_header.m, hdr.int_header.rsvd1,
            hdr.int_header.rsvd2, hdr.int_header.hop_metadata_len,
            hdr.int_header.remaining_hop_cnt,
            hdr.int_header.instruction_mask_0003,
            hdr.int_header.instruction_mask_0407,
            hdr.int_header.instruction_mask_0811,
            hdr.int_header.instruction_mask_1215,
            hdr.int_header.rsvd3
        });
        meta.fwd_metadata.checksum_state = ck.get_state();
        transition accept;
    }
}

control EgressDeparserImpl(packet_out packet,
                           out empty_metadata_t clone_e2e_meta,
                           out empty_metadata_t recirculate_meta,
                           inout headers hdr,
                           in metadata meta,
                           in psa_egress_output_metadata_t istd,
                           in psa_egress_deparser_input_metadata_t edstd)
{
    InternetChecksum() ck;
    apply {
        if (hdr.ipv4.isValid()) {
            ck.clear();
            ck.add({
                hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.dscp, hdr.ipv4.ecn,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags, hdr.ipv4.fragOffset,
                hdr.ipv4.ttl, hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            });
            hdr.ipv4.hdrChecksum = ck.get();
        }

        // TCP/UDP header incremental checksum update.
        // Restore the checksum state partially calculated in the parser.
        ck.set_state(meta.fwd_metadata.checksum_state);

        // Add back relevant header fields, including new INT metadata
        if (hdr.ipv4.isValid()) {
            ck.add({
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                hdr.ipv4.totalLen
            });
        }

        if (hdr.intl4_shim.isValid()) {
            ck.add({
                    hdr.intl4_shim.int_type, hdr.intl4_shim.rsvd1,
                    hdr.intl4_shim.len, hdr.intl4_shim.dscp, hdr.intl4_shim.rsvd2
                });
        }

        if (hdr.int_header.isValid()) {
            ck.add({
                    hdr.int_header.ver, hdr.int_header.rep,
                    hdr.int_header.c, hdr.int_header.e,
                    hdr.int_header.m, hdr.int_header.rsvd1,
                    hdr.int_header.rsvd2, hdr.int_header.hop_metadata_len,
                    hdr.int_header.remaining_hop_cnt,
                    hdr.int_header.instruction_mask_0003,
                    hdr.int_header.instruction_mask_0407,
                    hdr.int_header.instruction_mask_0811,
                    hdr.int_header.instruction_mask_1215,
                    hdr.int_header.rsvd3
                });
        }

        if (hdr.int_switch_id.isValid()) {
            ck.add({hdr.int_switch_id.switch_id});
        }

        if (hdr.int_level1_port_ids.isValid()) {
            ck.add({
                    hdr.int_level1_port_ids.ingress_port_id,
                    hdr.int_level1_port_ids.egress_port_id
                });
        }

        if (hdr.int_hop_latency.isValid()) {
            ck.add({hdr.int_hop_latency.hop_latency});
        }

        if (hdr.int_q_occupancy.isValid()) {
            ck.add({
                    hdr.int_q_occupancy.q_id,
                    hdr.int_q_occupancy.q_occupancy
                });
        }

        if (hdr.int_ingress_tstamp.isValid()) {
            ck.add({hdr.int_ingress_tstamp.ingress_tstamp});
        }

        if (hdr.int_egress_tstamp.isValid()) {
            ck.add({hdr.int_egress_tstamp.egress_tstamp});
        }

        if (hdr.int_level2_port_ids.isValid()) {
            ck.add({
                    hdr.int_level2_port_ids.ingress_port_id,
                    hdr.int_level2_port_ids.egress_port_id
                });
        }

        if (hdr.int_egress_port_tx_util.isValid()) {
            ck.add({hdr.int_egress_port_tx_util.egress_port_tx_util});
        }

        if (hdr.tcp.isValid()) {
            ck.add({
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNo,
                hdr.tcp.ackNo,
                hdr.tcp.dataOffset, hdr.tcp.res,
                hdr.tcp.flags,
                hdr.tcp.window,
                hdr.tcp.urgentPtr
            });
            hdr.tcp.checksum = ck.get();
        }

        if (hdr.udp.isValid()) {
            ck.add({
                hdr.udp.srcPort,
                hdr.udp.dstPort,
                hdr.udp.length_
            });

            // If hdr.udp.checksum was received as 0, we
            // should never change it.  If the calculated checksum is
            // 0, send all 1 bits instead.
            if (hdr.udp.checksum != 0) {
                hdr.udp.checksum = ck.get();
                if (hdr.udp.checksum == 0) {
                    hdr.udp.checksum = 0xffff;
                }
            }
        }

        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.intl4_shim);
        packet.emit(hdr.int_header);
        packet.emit(hdr.int_switch_id);
        packet.emit(hdr.int_level1_port_ids);
        packet.emit(hdr.int_hop_latency);
        packet.emit(hdr.int_q_occupancy);
        packet.emit(hdr.int_ingress_tstamp);
        packet.emit(hdr.int_egress_tstamp);
        packet.emit(hdr.int_level2_port_ids);
        packet.emit(hdr.int_egress_port_tx_util);
    }
}

/* This information isn't provided by PSA currently */
#define Q_ID        0xFF
#define Q_OCCUPANCY 0xFFFFFF
#define PORT_UTIL   13

control Int_metadata_insert(inout headers hdr,
        in int_metadata_t int_metadata,
        in bridged_ingress_input_metadata_t bridged_istd,
        in psa_egress_input_metadata_t istd)
{
    apply{
        // Bit 0: switch ID
        if (0 != hdr.intl4.instruction_mask_0003 & (1 << 0)) {
            hdr.int_switch_id.setValid();
            hdr.int_switch_id.switch_id = int_metadata.switch_id;
        }
        
        // Bit 1: Level 1 Ingress Port ID + Egress Port ID (2 bytes each)
        if (0 != hdr.intl4.instruction_mask_0003 & (1 << 1)) {
            hdr.int_level1_port_ids.setValid();
            hdr.int_level1_port_ids.ingress_port_id =
                (bit<16>) bridged_istd.ingress_port;
            hdr.int_level1_port_ids.egress_port_id =
                (bit<16>) istd.egress_port;
        }
        
        // Bit 2: Hop latency
        if (0 != hdr.intl4.instruction_mask_0003 & (1 << 2)) {
            hdr.int_hop_latency.setValid();
            hdr.int_hop_latency.hop_latency =
                (bit<32>) (istd.egress_timestamp - istd.ingress_timestamp);
        }
        
        // Bit 3: Queue ID
        if (0 != hdr.intl4.instruction_mask_0003 & (1 << 3)) {
            hdr.int_q_occupancy.setValid();
            hdr.int_q_occupancy.q_id = Q_ID;
            hdr.int_q_occupancy.q_occupancy = Q_OCCUPANCY;
        }
        
        // Bit 4: Ingress timestamp
        if (0 != hdr.intl4.instruction_mask_0407 & (1 << 0)) {
            hdr.int_ingress_tstamp.setValid();
            hdr.int_ingress_tstamp.ingress_tstamp =
                (bit<32>) bridged_istd.ingress_timestamp;
        }
        
        // Bit 5: Egress timestamp
        if (0 != hdr.intl4.instruction_mask_0407 & (1 << 1)) {
            hdr.int_egress_tstamp.setValid();
            hdr.int_egress_tstamp.egress_tstamp =
                (bit<32>) istd.egress_timestamp;
        }
        
        // Bit 6: Level 2 Ingress Port ID + Egress Port ID (4 bytes each)
        if (0 != hdr.intl4.instruction_mask_0407 & (1 << 2)) {
            hdr.int_level2_port_ids.setValid();
            hdr.int_level2_port_ids.ingress_port_id = /* FINISH */;
            hdr.int_level2_port_ids.egress_port_id = /* FINISH */;
        }
        
        // Bit 7: Egress port Tx utilization
        if (0 != hdr.intl4.instruction_mask_0407 & (1 << 3)) {
            hdr.int_egress_port_tx_util.setValid();
            hdr.int_egress_port_tx_util.egress_port_tx_util = PORT_UTIL;
        }
        
        // ...reserved...
        
        // Bit 15: Checksum complement
        // FINISH
    }
}

control Int_outer_encap(inout headers hdr,
        in int_metadata_t int_metadata)
{
    action int_update_ipv4() {
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + int_metadata.insert_byte_cnt;
    }
    action int_update_shim() {
        hdr.intl4_shim.len = hdr.intl4_shim.len + int_metadata.int_hdr_word_len;
    }

    apply{
        if (hdr.ipv4.isValid()) {
            int_update_ipv4();
        }
        /* Add: UDP length update if you support UDP */

        if (hdr.intl4_shim.isValid()) {
            int_update_shim();
        }
    }
}

control Int_ingress(inout metadata meta,
                    in psa_ingress_input_metadata_t  istd)
{
    action bridge_ingress_istd() {
        meta.bridged_istd.ingress_port = istd.ingress_port;
        meta.bridged_istd.ingress_timestamp = istd.ingress_timestamp;
    }
    apply{
        bridge_ingress_istd();
    }
}

control Int_egress(inout headers hdr,
                   inout metadata meta,
                   in    psa_egress_input_metadata_t  istd)
{
    action int_hop_cnt_exceeded() {
        hdr.int_header.e = 1;
    }
    action int_mtu_limit_hit() {
        hdr.int_header.m = 1;
    }
    action int_hop_cnt_decrement() {
        hdr.int_header.remaining_hop_cnt =
            hdr.int_header.remaining_hop_cnt - 1;
    }
    action int_transit(bit<32> switch_id, bit<16> l3_mtu) {
        meta.int_metadata.switch_id = switch_id;
        meta.int_metadata.insert_byte_cnt =
            (bit<16>) hdr.int_header.hop_metadata_len << 2;
        meta.int_metadata.int_hdr_word_len =
            (bit<8>) hdr.int_header.hop_metadata_len;
        meta.fwd_metadata.l3_mtu = l3_mtu;
    }
    table int_prep {
        key = {}
        actions = {int_transit;}
    }

    Int_metadata_insert() int_metadata_insert;
    Int_outer_encap() int_outer_encap;

    apply{
        if(hdr.int_header.isValid()) {
            if(hdr.int_header.remaining_hop_cnt == 0
                    || hdr.int_header.e == 1) {
                int_hop_cnt_exceeded();
            } else if ((hdr.int_header.instruction_mask_0811 ++
                        hdr.int_header.instruction_mask_1215)
                        & 8w0xFE == 0 ) {
                /* v1.0 spec allows two options for handling unsupported
                 * INT instructions. This exmple code skips the entire
                 * hop if any unsupported bit (bit 8 to 14 in v1.0 spec) is set.
                 */
                int_prep.apply();
                // check MTU limit
                if (hdr.ipv4.totalLen + meta.int_metadata.insert_byte_cnt
                        > meta.fwd_metadata.l3_mtu) {
                    int_mtu_limit_hit();
                } else {
                    int_hop_cnt_decrement();
                    int_metadata_insert.apply(hdr,
                                              meta.int_metadata,
                                              meta.bridged_istd,
                                              istd);
                    int_outer_encap.apply(hdr, meta.int_metadata);
                }
            }
        }
    }
}

control ingress(inout headers hdr,
                inout metadata meta,
                in    psa_ingress_input_metadata_t  istd,
                inout psa_ingress_output_metadata_t ostd)
{
    Int_ingress() int_ingress;
    apply{
        /* ... ingress code here ... */
        int_ingress.apply(meta, istd);
        /* ... ingress code here ... */
    }
}

control egress(inout headers hdr,
               inout metadata meta,
               in    psa_egress_input_metadata_t  istd,
               inout psa_egress_output_metadata_t ostd)
{
    Int_egress() int_egress;
    apply{
        /* ... egress code here ... */
        int_egress.apply(hdr, meta, istd);
        /* ... egress code here ... */
    }
}

IngressPipeline(IngressParserImpl(),
                ingress(),
                IngressDeparserImpl()) ip;

EgressPipeline(EgressParserImpl(),
               egress(),
               EgressDeparserImpl()) ep;

PSA_SWITCH(ip, ep) main;