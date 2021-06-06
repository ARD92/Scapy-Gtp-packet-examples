__author__ = "Aravind Prabhakar"

"""
config_gtp_flex.py: 

Generate Junos set configuration for GTPv1 and v2 filtering using flex filters which can be used on vMX/MX.
Usage: python config_gtp_flex.py -term <number of unique teid/src/dst ip> -iptype <v4inv4/v4inv6/v6inv4/v6inv6>
add -base optionally to generate the common base configuration

In order to create a scaled config, /32 prefixes for IPv4 and /128 prefixes for IPv6 are used in the filter prefix matches
This allows to ensure max scale can be tested. 
The number teid terms creates unique TEID values. The source prefix and destination prefixes are also unique for each TEID.
we increment by "1" for every TEID so that we can easily track during testing the number of packet matches.
Starting TEID Range cannot be "1" because this is used in the base template config and should be the first term hit in the filter

example: python config_gtp_flex.py -term 10 -base -iptype v4inv4
         python config_gtp_flex.py -term 10 -iptype v4inv6
         python config_gtp_flex.py -term 10 -iptype v6inv6
         python config_gtp_flex.py -term 10 -iptype v6inv4
""" 

import argparse
import yaml
import os
from netaddr import *

parser = argparse.ArgumentParser()
parser.add_argument('-term', action='store', dest='TERM', type=str, default=None)
parser.add_argument('-base', action='store_true',dest='BASE', help='base template for flexfilters.')
parser.add_argument('-iptype', action='store', dest='IPTYPE', type=str, default=None, help='terms for flexfilters. possible options are v4inv4, v4inv6, v6inv6')
args=parser.parse_args()

# Starting TEID Range cannot be "1" because this is used in the base template config and should be the first term hit in the filter
STARTING_TEID_RANGE = 1000
INNER_IPV4_SRC_ADDRESS = "1.1.1.1/24"
INNER_IPV4_DST_ADDRESS = "2.1.1.1/24"
INNER_IPV6_SRC_ADDRESS = "2001:1990:fc90:3721::4:1a/64"
INNER_IPV6_DST_ADDRESS = "2001:1890:fc80:3721::4:1a/64"

"""
Base template configuration.
v4 in v4 , v4 in v6 use the same flex matches INNER-SRC-IP, INNER-DST-IP

v6 in v6 ,  uses  flex matches V6-IN-V6-INNER-SRC-IP-T1, V6-IN-V6-INNER-SRC-IP-T2, V6-IN-V6-INNER-SRC-IP-T3, V6-IN-V6-INNER-SRC-IP-T4
                               V6-IN-V6-INNER-DST-IP-T1, V6-IN-V6-INNER-DST-IP-T2, V6-IN-V6-INNER-DST-IP-T3. V6-IN-V6-INNER-DST-IP-T4

V6 in V4 uses flex matches V6-INNER-SRC-IP-T1, V6-INNER-SRC-IP-T2, V6-INNER-SRC-IP-T3, V6-INNER-SRC-IP-T4
                           V6-INNER-DST-IP-T1, V6-INNER-DST-IP-T2, V6-INNER-DST-IP-T3, V6-INNER-DST-IP-T4 

GTPTEID and GTPVer is used as common flex match for all combinations

Cos mappings are reused between ipv4 and ipv6 

WIP: currently GTPv1 is matched against 0x30 and GTPv2 against 0x40. This can vary. Handle this in ranges instead of mask.
"""
def config_template():
    config = [
    'set firewall flexible-match GTPVer match-start layer-4',
    'set firewall flexible-match GTPVer byte-offset 8',
    'set firewall flexible-match GTPVer bit-offset 0',
    'set firewall flexible-match GTPVer bit-length 5',
    'set firewall flexible-match GTPTEID match-start layer-4',
    'set firewall flexible-match GTPTEID byte-offset 12',
    'set firewall flexible-match GTPTEID bit-offset 0',
    'set firewall flexible-match GTPTEID bit-length 32',
    'set firewall flexible-match INNER-SRC-IP match-start layer-4',
    'set firewall flexible-match INNER-SRC-IP byte-offset 28',
    'set firewall flexible-match INNER-SRC-IP bit-offset 0',
    'set firewall flexible-match INNER-SRC-IP bit-length 32',
    'set firewall flexible-match INNER-DST-IP match-start layer-4',
    'set firewall flexible-match INNER-DST-IP byte-offset 32',
    'set firewall flexible-match INNER-DST-IP bit-offset 0',
    'set firewall flexible-match INNER-DST-IP bit-length 32',
    'set firewall flexible-match INNER-SRC-PORT match-start layer-4',
    'set firewall flexible-match INNER-SRC-PORT byte-offset 36',
    'set firewall flexible-match INNER-SRC-PORT bit-offset 0',
    'set firewall flexible-match INNER-SRC-PORT bit-length 16',
    'set firewall flexible-match INNER-DST-PORT match-start layer-4',
    'set firewall flexible-match INNER-DST-PORT byte-offset 38',
    'set firewall flexible-match INNER-DST-PORT bit-offset 0',
    'set firewall flexible-match INNER-DST-PORT bit-length 16',
    'set firewall flexible-match V6-INNER-SRC-IP-T1 match-start layer-4',
    'set firewall flexible-match V6-INNER-SRC-IP-T1 byte-offset 24',
    'set firewall flexible-match V6-INNER-SRC-IP-T1 bit-offset 0',
    'set firewall flexible-match V6-INNER-SRC-IP-T1 bit-length 32',
    'set firewall flexible-match V6-INNER-SRC-IP-T2 match-start layer-4',
    'set firewall flexible-match V6-INNER-SRC-IP-T2 byte-offset 28',
    'set firewall flexible-match V6-INNER-SRC-IP-T2 bit-offset 0',
    'set firewall flexible-match V6-INNER-SRC-IP-T2 bit-length 32',
    'set firewall flexible-match V6-INNER-SRC-IP-T3 match-start layer-4',
    'set firewall flexible-match V6-INNER-SRC-IP-T3 byte-offset 32',
    'set firewall flexible-match V6-INNER-SRC-IP-T3 bit-offset 0',
    'set firewall flexible-match V6-INNER-SRC-IP-T3 bit-length 32',
    'set firewall flexible-match V6-INNER-SRC-IP-T4 match-start layer-4',
    'set firewall flexible-match V6-INNER-SRC-IP-T4 byte-offset 36',
    'set firewall flexible-match V6-INNER-SRC-IP-T4 bit-offset 0',
    'set firewall flexible-match V6-INNER-SRC-IP-T4 bit-length 32',
    'set firewall flexible-match V6-INNER-DST-IP-T1 match-start layer-4',
    'set firewall flexible-match V6-INNER-DST-IP-T1 byte-offset 40',
    'set firewall flexible-match V6-INNER-DST-IP-T1 bit-offset 0',
    'set firewall flexible-match V6-INNER-DST-IP-T1 bit-length 32',
    'set firewall flexible-match V6-INNER-DST-IP-T2 match-start layer-4',
    'set firewall flexible-match V6-INNER-DST-IP-T2 byte-offset 44',
    'set firewall flexible-match V6-INNER-DST-IP-T2 bit-offset 0',
    'set firewall flexible-match V6-INNER-DST-IP-T2 bit-length 32',
    'set firewall flexible-match V6-INNER-DST-IP-T3 match-start layer-4',
    'set firewall flexible-match V6-INNER-DST-IP-T3 byte-offset 48',
    'set firewall flexible-match V6-INNER-DST-IP-T3 bit-offset 0',
    'set firewall flexible-match V6-INNER-DST-IP-T3 bit-length 32',
    'set firewall flexible-match V6-INNER-DST-IP-T4 match-start layer-4',
    'set firewall flexible-match V6-INNER-DST-IP-T4 byte-offset 52',
    'set firewall flexible-match V6-INNER-DST-IP-T4 bit-offset 0',
    'set firewall flexible-match V6-INNER-DST-IP-T4 bit-length 32',
    'set firewall flexible-match V6-IN-V6-INNER-SRC-IP-T1 match-start layer-4',
    'set firewall flexible-match V6-IN-V6-INNER-SRC-IP-T1 byte-offset 24',
    'set firewall flexible-match V6-IN-V6-INNER-SRC-IP-T1 bit-offset 0',
    'set firewall flexible-match V6-IN-V6-INNER-SRC-IP-T1 bit-length 32',
    'set firewall flexible-match V6-IN-V6-INNER-SRC-IP-T2 match-start layer-4',
    'set firewall flexible-match V6-IN-V6-INNER-SRC-IP-T2 byte-offset 28',
    'set firewall flexible-match V6-IN-V6-INNER-SRC-IP-T2 bit-offset 0',
    'set firewall flexible-match V6-IN-V6-INNER-SRC-IP-T2 bit-length 32',
    'set firewall flexible-match V6-IN-V6-INNER-SRC-IP-T3 match-start layer-4',
    'set firewall flexible-match V6-IN-V6-INNER-SRC-IP-T3 byte-offset 32',
    'set firewall flexible-match V6-IN-V6-INNER-SRC-IP-T3 bit-offset 0',
    'set firewall flexible-match V6-IN-V6-INNER-SRC-IP-T3 bit-length 32',
    'set firewall flexible-match V6-IN-V6-INNER-SRC-IP-T4 match-start layer-4',
    'set firewall flexible-match V6-IN-V6-INNER-SRC-IP-T4 byte-offset 36',
    'set firewall flexible-match V6-IN-V6-INNER-SRC-IP-T4 bit-offset 0',
    'set firewall flexible-match V6-IN-V6-INNER-SRC-IP-T4 bit-length 32',
    'set firewall flexible-match V6-IN-V6-INNER-DST-IP-T1 match-start layer-4',
    'set firewall flexible-match V6-IN-V6-INNER-DST-IP-T1 byte-offset 40',
    'set firewall flexible-match V6-IN-V6-INNER-DST-IP-T1 bit-offset 0',
    'set firewall flexible-match V6-IN-V6-INNER-DST-IP-T1 bit-length 32',
    'set firewall flexible-match V6-IN-V6-INNER-DST-IP-T2 match-start layer-4',
    'set firewall flexible-match V6-IN-V6-INNER-DST-IP-T2 byte-offset 44',
    'set firewall flexible-match V6-IN-V6-INNER-DST-IP-T2 bit-offset 0',
    'set firewall flexible-match V6-IN-V6-INNER-DST-IP-T2 bit-length 32',
    'set firewall flexible-match V6-IN-V6-INNER-DST-IP-T3 match-start layer-4',
    'set firewall flexible-match V6-IN-V6-INNER-DST-IP-T3 byte-offset 48',
    'set firewall flexible-match V6-IN-V6-INNER-DST-IP-T3 bit-offset 0',
    'set firewall flexible-match V6-IN-V6-INNER-DST-IP-T3 bit-length 32',
    'set firewall flexible-match V6-IN-V6-INNER-DST-IP-T4 match-start layer-4',
    'set firewall flexible-match V6-IN-V6-INNER-DST-IP-T4 byte-offset 52',
    'set firewall flexible-match V6-IN-V6-INNER-DST-IP-T4 bit-offset 0',
    'set firewall flexible-match V6-IN-V6-INNER-DST-IP-T4 bit-length 32',

    'set class-of-service policy-map GTPv1 inet-precedence proto-ip code-point 001',
    'set class-of-service policy-map GTPv2 inet-precedence proto-ip code-point 010',
    'set class-of-service policy-map TEID inet-precedence proto-ip code-point 011',
    'set class-of-service policy-map INNER-SRC inet-precedence proto-ip code-point 100',
    'set class-of-service policy-map INNER-DST inet-precedence proto-ip code-point 101',
    'set class-of-service policy-map INNER-DST-PORT inet-precedence proto-ip code-point 111',
    'set class-of-service policy-map INNER-SRC-PORT inet-precedence proto-ip code-point 110',
    'set class-of-service policy-map IPV6-SRC-T1 dscp-ipv6 proto-ip code-point 000001',
    'set class-of-service policy-map IPV6-SRC-T2 dscp-ipv6 proto-ip code-point 000010',
    'set class-of-service policy-map IPV6-SRC-T3 dscp-ipv6 proto-ip code-point 000011',
    'set class-of-service policy-map IPV6-SRC-T4 dscp-ipv6 proto-ip code-point 000100',
    'set class-of-service policy-map IPV6-DST-T1 dscp-ipv6 proto-ip code-point 000101',
    'set class-of-service policy-map IPV6-DST-T2 dscp-ipv6 proto-ip code-point 000110',
    'set class-of-service policy-map IPV6-DST-T3 dscp-ipv6 proto-ip code-point 000111',
    'set class-of-service policy-map IPV6-DST-T4 dscp-ipv6 proto-ip code-point 001000',

    'set firewall family inet filter gtp-v1-stage1-classify term GTPv1 from protocol udp',
    'set firewall family inet filter gtp-v1-stage1-classify term GTPv1 from port 2152',
    'set firewall family inet filter gtp-v1-stage1-classify term GTPv1 from flexible-match-mask mask-in-hex 0xe0000000',
    'set firewall family inet filter gtp-v1-stage1-classify term GTPv1 from flexible-match-mask prefix 0x30',
    'set firewall family inet filter gtp-v1-stage1-classify term GTPv1 from flexible-match-mask flexible-mask-name GTPVer',
    'set firewall family inet filter gtp-v1-stage1-classify term GTPv1 then policy-map GTPv1',
    'set firewall family inet filter gtp-v1-stage1-classify term GTPv1 then count count-GTPv1',
    'set firewall family inet filter gtp-v1-stage1-classify term GTPv1 then accept',
    'set firewall family inet filter gtp-v1-stage1-classify term GTPv2 from protocol udp',
    'set firewall family inet filter gtp-v1-stage1-classify term GTPv2 from port 2123',
    'set firewall family inet filter gtp-v1-stage1-classify term GTPv2 from flexible-match-mask mask-in-hex 0xe8000000',
    'set firewall family inet filter gtp-v1-stage1-classify term GTPv2 from flexible-match-mask prefix 0x40',
    'set firewall family inet filter gtp-v1-stage1-classify term GTPv2 from flexible-match-mask flexible-mask-name GTPVer',
    'set firewall family inet filter gtp-v1-stage1-classify term GTPv2 then policy-map GTPv2',
    'set firewall family inet filter gtp-v1-stage1-classify term GTPv2 then count count-GTPv2',
    'set firewall family inet filter gtp-v1-stage1-classify term GTPv2 then accept',
    'set firewall family inet filter gtp-v1-stage1-classify term NON-GTP then count NON-GTP-HITS',
    'set firewall family inet filter gtp-v1-stage1-classify term NON-GTP then discard',

    'set firewall family inet filter gtp-v1-stage2-filter-teid term 1 from policy-map-except GTPv1',
    'set firewall family inet filter gtp-v1-stage2-filter-teid term 1 then accept',
    'set firewall family inet filter gtp-v1-stage3-source-filter term 1 from policy-map-except TEID',
    'set firewall family inet filter gtp-v1-stage3-source-filter term 1 then accept',
    'set firewall family inet filter gtp-v1-stage4-dest-filter term 1 from policy-map-except INNER-SRC',
    'set firewall family inet filter gtp-v1-stage4-dest-filter term 1 then accept',

    'set firewall family inet6 filter gtp-v1-stage1-classify-v6 term GTPv1 from payload-protocol udp',
    'set firewall family inet6 filter gtp-v1-stage1-classify-v6 term GTPv1 from port 2152',
    'set firewall family inet6 filter gtp-v1-stage1-classify-v6 term GTPv1 from flexible-match-mask mask-in-hex 0xe0000000',
    'set firewall family inet6 filter gtp-v1-stage1-classify-v6 term GTPv1 from flexible-match-mask prefix 0x30',
    'set firewall family inet6 filter gtp-v1-stage1-classify-v6 term GTPv1 from flexible-match-mask flexible-mask-name GTPVer',
    'set firewall family inet6 filter gtp-v1-stage1-classify-v6 term GTPv1 then policy-map GTPv1',
    'set firewall family inet6 filter gtp-v1-stage1-classify-v6 term GTPv1 then count count-GTPv1-v6',
    'set firewall family inet6 filter gtp-v1-stage1-classify-v6 term GTPv1 then accept',
    'set firewall family inet6 filter gtp-v1-stage1-classify-v6 term GTPv2 from payload-protocol udp',
    'set firewall family inet6 filter gtp-v1-stage1-classify-v6 term GTPv2 from port 2123',
    'set firewall family inet6 filter gtp-v1-stage1-classify-v6 term GTPv2 from flexible-match-mask mask-in-hex 0xe8000000',
    'set firewall family inet6 filter gtp-v1-stage1-classify-v6 term GTPv2 from flexible-match-mask prefix 0x40',
    'set firewall family inet6 filter gtp-v1-stage1-classify-v6 term GTPv2 from flexible-match-mask flexible-mask-name GTPVer',
    'set firewall family inet6 filter gtp-v1-stage1-classify-v6 term GTPv2 then policy-map GTPv2',
    'set firewall family inet6 filter gtp-v1-stage1-classify-v6 term GTPv2 then count count-GTPv2-v6',
    'set firewall family inet6 filter gtp-v1-stage1-classify-v6 term NON-GTP-V6 then count NON-GTP-HITS-V6',
    'set firewall family inet6 filter gtp-v1-stage1-classify-v6 term NON-GTP-V6 then discard',

    'set firewall family inet6 filter gtp-v1-stage2-filter-teid-v6 term 1 from policy-map-except GTPv1',
    'set firewall family inet6 filter gtp-v1-stage2-filter-teid-v6 term 1 then accept',
    'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term 1 from policy-map-except TEID',
    'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term 1 then accept',
    'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term 1 from policy-map-except INNER-SRC',
    'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term 1 then accept',
    ]
    with open('base_template','w') as f:
        for i in config:
            f.write(i)
            f.write('\n')
    f.close()

""" 
Generate scaled config for various types
"""
def scale_term(terms, version):
    term = STARTING_TEID_RANGE
    if version == 'v4inv4':
        src_prefix = IPNetwork(INNER_IPV4_SRC_ADDRESS).ip
        dst_prefix = IPNetwork(INNER_IPV4_DST_ADDRESS).ip
        with open('scaled_v4-in-v4_filters_{}_terms'.format(terms),'w') as f:
            for i in range(int(terms)):
                term = term+1
                sip = src_prefix + i
                print("source IP for term {} is {}".format(term,sip))
                dip = dst_prefix + i
                print("dest IP for term {} is {}".format(term, dip))
                print(50*"=")
                stage2=[
                'set firewall family inet filter gtp-v1-stage2-filter-teid term {} from flexible-match-mask mask-in-hex 0xffffffff'.format(term),
                'set firewall family inet filter gtp-v1-stage2-filter-teid term {} from flexible-match-mask prefix {}'.format(term, term),
                'set firewall family inet filter gtp-v1-stage2-filter-teid term {} from flexible-match-mask flexible-mask-name GTPTEID'.format(term),
                'set firewall family inet filter gtp-v1-stage2-filter-teid term {} then policy-map TEID'.format(term),
                'set firewall family inet filter gtp-v1-stage2-filter-teid term {} then count count-TEID-{}'.format(term,term),
                'set firewall family inet filter gtp-v1-stage2-filter-teid term {} then accept'.format(term)
                ]

                stage3=[
                'set firewall family inet filter gtp-v1-stage3-source-filter term {} from flexible-match-mask mask-in-hex 0xffffffff'.format(term),
                'set firewall family inet filter gtp-v1-stage3-source-filter term {} from flexible-match-mask prefix {}'.format(term, hex(sip)),
                'set firewall family inet filter gtp-v1-stage3-source-filter term {} from flexible-match-mask flexible-mask-name INNER-SRC-IP'.format(term),
                'set firewall family inet filter gtp-v1-stage3-source-filter term {} then policy-map INNER-SRC'.format(term),
                'set firewall family inet filter gtp-v1-stage3-source-filter term {} then count INNER-SRC-COUNT-{}'.format(term, str(sip)),
                'set firewall family inet filter gtp-v1-stage3-source-filter term {} then accept'.format(term)
                ]

                stage4=[
                'set firewall family inet filter gtp-v1-stage4-dest-filter term {} from flexible-match-mask mask-in-hex 0xffffffff'.format(term),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term {} from flexible-match-mask prefix {}'.format(term, hex(dip)),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term {} from flexible-match-mask flexible-mask-name INNER-DST-IP'.format(term),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term {} then policy-map INNER-DST'.format(term),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term {} then count INNER-DST-COUNT-{}'.format(term, str(dip)),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term {} then accept'.format(term)
                ]

                config = stage2+stage3+stage4
                for add in config:
                    f.write(add)
                    f.write('\n')
        f.close()    
        print("V4 in V4 terms configs saved in file scaled_v4-in-v4_filters_{}_terms".format(terms))

    elif version == "v4inv6":
        src_prefix = IPNetwork(INNER_IPV4_SRC_ADDRESS).ip
        dst_prefix = IPNetwork(INNER_IPV4_DST_ADDRESS).ip
        with open('scaled_v4-in-v6_filters_{}_terms'.format(terms),'w') as f:
            for i in range(int(terms)):
                term = term+i
                sip = src_prefix + i
                print("source IP for term {} is {}".format(term,sip))
                dip = dst_prefix + i
                print("dest IP for term {} is {}".format(term, dip))
                print(50*"=")
                stage2=[
                'set firewall family inet6 filter gtp-v1-stage2-filter-teid-v6 term {} from flexible-match-mask mask-in-hex 0xffffffff'.format(term),
                'set firewall family inet6 filter gtp-v1-stage2-filter-teid-v6 term {} from flexible-match-mask prefix {}'.format(term, term),
                'set firewall family inet6 filter gtp-v1-stage2-filter-teid-v6 term {} from flexible-match-mask flexible-mask-name GTPTEID'.format(term),
                'set firewall family inet6 filter gtp-v1-stage2-filter-teid-v6 term {} then policy-map TEID'.format(term),
                'set firewall family inet6 filter gtp-v1-stage2-filter-teid-v6 term {} then count count-TEID-{}-V6'.format(term, term),
                'set firewall family inet6 filter gtp-v1-stage2-filter-teid-v6 term {} then accept'.format(term)
                ]

                stage3=[
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term {} from flexible-match-mask mask-in-hex 0xffffffff'.format(term),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term {} from flexible-match-mask prefix {}'.format(term, hex(sip)),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term {} from flexible-match-mask flexible-mask-name INNER-SRC-IP'.format(term),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term {} then policy-map INNER-SRC'.format(term),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term {} then count V4-in-V6-INNER-SRC-COUNT-{}'.format(term, str(sip)),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term {} then accept'.format(term)
                ]

                stage4=[
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term {} from flexible-match-mask mask-in-hex 0xffffffff'.format(term),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term {} from flexible-match-mask prefix {}'.format(term, hex(dip)),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term {} from flexible-match-mask flexible-mask-name INNER-DST-IP'.format(term),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term {} then policy-map INNER-DST'.format(term),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term {} then count v4-in-v6-INNER-DST-COUNT-{}'.format(term, str(dip)),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term {} then accept'.format(term)
                ]

                config = stage2+stage3+stage4
                for add in config:
                    f.write(add)
                    f.write('\n')
        f.close()    
        print("V4 in V6 terms configs saved in file scaled_v4-in-v6_filters_{}_terms".format(terms))

    elif version == 'v6inv4':
        dst_prefix = IPNetwork(INNER_IPV6_SRC_ADDRESS).ip
        src_prefix = IPNetwork(INNER_IPV6_DST_ADDRESS).ip
        with open('scaled_v6-in-v4_filters_{}_terms'.format(terms),'w') as f1:
            for i in range(int(terms)):
                term = term+1
                sip = src_prefix + i
                print("source IP for term {} is {}".format(term,sip))
                dip = dst_prefix + i
                print("dest IP for term {} is {}".format(term, dip))
                print(50*"=")
                stage2=[
                'set firewall family inet filter gtp-v1-stage2-filter-teid term {} from flexible-match-mask mask-in-hex 0xffffffff'.format(term),
                'set firewall family inet filter gtp-v1-stage2-filter-teid term {} from flexible-match-mask prefix {}'.format(term, term),
                'set firewall family inet filter gtp-v1-stage2-filter-teid term {} from flexible-match-mask flexible-mask-name GTPTEID'.format(term),
                'set firewall family inet filter gtp-v1-stage2-filter-teid term {} then policy-map TEID'.format(term),
                'set firewall family inet filter gtp-v1-stage2-filter-teid term {} then count count-TEID-{}'.format(term,term),
                'set firewall family inet filter gtp-v1-stage2-filter-teid term {} then accept'.format(term)
                ]
                # remove characters "0x" 
                hex_sip = hex(sip)[2:]
                hex_dip = hex(dip)[2:]
                split_val_src = []
                split_val_dst = []
                for split in range(1,5):
                    hex_split_s = hex_sip[:8]
                    hex_split_d = hex_dip[:8]
                    hex_sip = hex_sip[8:]
                    hex_dip = hex_dip[8:]
                    split_val_src.append('0x' + hex_split_s)
                    split_val_dst.append('0x' + hex_split_d)
               
                stage3=[
                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t1-{} from flexible-match-mask mask-in-hex 0xffffffff'.format(sip),
                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t1-{} from flexible-match-mask prefix {}'.format(sip, split_val_src[0]),
                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t1-{} from flexible-match-mask flexible-mask-name V6-INNER-SRC-IP-T1'.format(sip),
                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t1-{} then policy-map IPV6-SRC-T1'.format(sip),
                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t1-{} then next term'.format(sip),

                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t2-{} from flexible-match-mask mask-in-hex 0xffffffff'.format(sip),
                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t2-{} from flexible-match-mask prefix {}'.format(sip, split_val_src[1]),
                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t2-{} from flexible-match-mask flexible-mask-name V6-INNER-SRC-IP-T2'.format(sip),
                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t2-{} from policy-map IPV6-SRC-T1'.format(sip),
                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t2-{} then policy-map IPV6-SRC-T2'.format(sip),
                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t2-{} then next term'.format(sip),

                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t3-{} from flexible-match-mask mask-in-hex 0xffffffff'.format(sip),
                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t3-{} from flexible-match-mask prefix {}'.format(sip, split_val_src[2]),
                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t3-{} from flexible-match-mask flexible-mask-name V6-INNER-SRC-IP-T3'.format(sip),
                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t3-{} from policy-map IPV6-SRC-T1'.format(sip),
                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t3-{} from policy-map IPV6-SRC-T2'.format(sip),
                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t3-{} then policy-map IPV6-SRC-T3'.format(sip),
                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t3-{} then next term'.format(sip),

                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t4-{} from flexible-match-mask mask-in-hex 0xffffffff'.format(sip),
                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t4-{} from flexible-match-mask prefix {}'.format(sip, split_val_src[3]),
                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t4-{} from flexible-match-mask flexible-mask-name V6-INNER-SRC-IP-T4'.format(sip),
                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t4-{} from policy-map IPV6-SRC-T1'.format(sip),
                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t4-{} from policy-map IPV6-SRC-T2'.format(sip),
                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t4-{} from policy-map IPV6-SRC-T3'.format(sip),
                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t4-{} then policy-map INNER-SRC'.format(sip),
                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t4-{} then count ipv6-count-{}'.format(sip, sip),
                'set firewall family inet filter gtp-v1-stage3-source-filter term ipv6-t4-{} then accept'.format(sip)
                ]

                stage4=[
                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t1-{} from flexible-match-mask mask-in-hex 0xffffffff'.format(dip),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t1-{} from flexible-match-mask prefix {}'.format(dip, split_val_dst[0]),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t1-{} from flexible-match-mask flexible-mask-name V6-INNER-DST-IP-T1'.format(dip),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t1-{} then policy-map IPV6-DST-T1'.format(dip),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t1-{} then next term'.format(dip),

                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t2-{} from flexible-match-mask mask-in-hex 0xffffffff'.format(dip),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t2-{} from flexible-match-mask prefix {}'.format(dip, split_val_dst[1]),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t2-{} from flexible-match-mask flexible-mask-name V6-INNER-DST-IP-T2'.format(dip),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t2-{} from policy-map IPV6-DST-T1'.format(dip),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t2-{} then policy-map IPV6-DST-T2'.format(dip),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t2-{} then next term'.format(dip),

                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t3-{} from flexible-match-mask mask-in-hex 0xffffffff'.format(dip),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t3-{} from flexible-match-mask prefix {}'.format(dip, split_val_dst[2]),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t3-{} from flexible-match-mask flexible-mask-name V6-INNER-DST-IP-T3'.format(dip),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t3-{} from policy-map IPV6-DST-T1'.format(dip),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t3-{} from policy-map IPV6-DST-T2'.format(dip),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t3-{} then policy-map IPV6-DST-T3'.format(dip),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t3-{} then next term'.format(dip),

                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t4-{} from flexible-match-mask mask-in-hex 0xffffffff'.format(dip),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t4-{} from flexible-match-mask prefix {}'.format(dip, split_val_dst[3]),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t4-{} from flexible-match-mask flexible-mask-name V6-INNER-DST-IP-T4'.format(dip),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t4-{} from policy-map IPV6-DST-T1'.format(dip),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t4-{} from policy-map IPV6-DST-T2'.format(dip),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t4-{} from policy-map IPV6-DST-T3'.format(dip),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t4-{} then policy-map INNER-DST'.format(dip),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t4-{} then count ipv6-count-{}'.format(dip, dip),
                'set firewall family inet filter gtp-v1-stage4-dest-filter term ipv6-t4-{} then accept'.format(dip),
                ]
                config = stage2+stage3+stage4
                for add in config:
                    f1.write(add)
                    f1.write('\n')
        f1.close()    
        print("V6 in V4 terms configs saved in file scaled_v6-in-v4_filters_{}_terms".format(terms))

    elif version == 'v6inv6':
        dst_prefix = IPNetwork(INNER_IPV6_SRC_ADDRESS).ip
        src_prefix = IPNetwork(INNER_IPV6_DST_ADDRESS).ip
        with open('scaled_v6-in-v6_filters_{}_terms'.format(terms),'w') as f1:
            for i in range(int(terms)):
                term = term+1
                sip = src_prefix + i
                print("source IP for term {} is {}".format(term,sip))
                dip = dst_prefix + i
                print("dest IP for term {} is {}".format(term, dip))
                print(50*"=")
                stage2=[
                'set firewall family inet6 filter gtp-v1-stage2-filter-teid-v6 term {} from flexible-match-mask mask-in-hex 0xffffffff'.format(term),
                'set firewall family inet6 filter gtp-v1-stage2-filter-teid-v6 term {} from flexible-match-mask prefix {}'.format(term, term),
                'set firewall family inet6 filter gtp-v1-stage2-filter-teid-v6 term {} from flexible-match-mask flexible-mask-name GTPTEID'.format(term),
                'set firewall family inet6 filter gtp-v1-stage2-filter-teid-v6 term {} then policy-map TEID'.format(term),
                'set firewall family inet6 filter gtp-v1-stage2-filter-teid-v6 term {} then count count-TEID-{}-V6'.format(term, term),
                'set firewall family inet6 filter gtp-v1-stage2-filter-teid-v6 term {} then accept'.format(term)
                ]
                # remove characters "0x" 
                hex_sip = hex(sip)[2:]
                hex_dip = hex(dip)[2:]
                split_val_src = []
                split_val_dst = []
                for split in range(1,5):
                    hex_split_s = hex_sip[:8]
                    hex_split_d = hex_dip[:8]
                    hex_sip = hex_sip[8:]
                    hex_dip = hex_dip[8:]
                    # add characters "0x" back
                    split_val_src.append('0x' + hex_split_s)
                    split_val_dst.append('0x' + hex_split_d)

                stage3=[
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t1-{} from flexible-match-mask mask-in-hex 0xffffffff'.format(sip),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t1-{} from flexible-match-mask prefix {}'.format(sip, split_val_src[0]),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t1-{} from flexible-match-mask flexible-mask-name V6-IN-V6-INNER-SRC-IP-T1'.format(sip),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t1-{} then policy-map IPV6-SRC-T1'.format(sip),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t1-{} then next term'.format(sip),

                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t2-{} from flexible-match-mask mask-in-hex 0xffffffff'.format(sip),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t2-{} from flexible-match-mask prefix {}'.format(sip, split_val_src[1]),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t2-{} from flexible-match-mask flexible-mask-name V6-IN-V6-INNER-SRC-IP-T2'.format(sip),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t2-{} from policy-map IPV6-SRC-T1'.format(sip),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t2-{} then policy-map IPV6-SRC-T2'.format(sip),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t2-{} then next term'.format(sip),

                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t3-{} from flexible-match-mask mask-in-hex 0xffffffff'.format(sip),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t3-{} from flexible-match-mask prefix {}'.format(sip, split_val_src[2]),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t3-{} from flexible-match-mask flexible-mask-name V6-IN-V6-INNER-SRC-IP-T3'.format(sip),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t3-{} from policy-map IPV6-SRC-T1'.format(sip),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t3-{} from policy-map IPV6-SRC-T2'.format(sip),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t3-{} then policy-map IPV6-SRC-T3'.format(sip),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t3-{} then next term'.format(sip),

                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t4-{} from flexible-match-mask mask-in-hex 0xffffffff'.format(sip),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t4-{} from flexible-match-mask prefix {}'.format(sip, split_val_src[3]),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t4-{} from flexible-match-mask flexible-mask-name V6-IN-V6-INNER-SRC-IP-T4'.format(sip),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t4-{} from policy-map IPV6-SRC-T1'.format(sip),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t4-{} from policy-map IPV6-SRC-T2'.format(sip),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t4-{} from policy-map IPV6-SRC-T3'.format(sip),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t4-{} then policy-map INNER-SRC'.format(sip),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t4-{} then count v6-in-v6-count-{}'.format(sip,sip),
                'set firewall family inet6 filter gtp-v1-stage3-source-filter-v6 term ipv6-t4-{} then accept'.format(sip),
                ]
                stage4=[
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t1-{} from flexible-match-mask mask-in-hex 0xffffffff'.format(dip),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t1-{} from flexible-match-mask prefix {}'.format(dip, split_val_dst[0]),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t1-{} from flexible-match-mask flexible-mask-name V6-IN-V6-INNER-DST-IP-T1'.format(dip),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t1-{} then policy-map IPV6-DST-T1'.format(dip),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t1-{} then next term'.format(dip),

                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t2-{} from flexible-match-mask mask-in-hex 0xffffffff'.format(dip),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t2-{} from flexible-match-mask prefix {}'.format(dip, split_val_dst[1]),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t2-{} from flexible-match-mask flexible-mask-name V6-IN-V6-INNER-DST-IP-T2'.format(dip),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t2-{} from policy-map IPV6-DST-T1'.format(dip),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t2-{} then policy-map IPV6-DST-T2'.format(dip),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t2-{} then next term'.format(dip),

                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t3-{} from flexible-match-mask mask-in-hex 0xffffffff'.format(dip),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t3-{} from flexible-match-mask prefix {}'.format(dip, split_val_dst[2]),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t3-{} from flexible-match-mask flexible-mask-name V6-IN-V6-INNER-DST-IP-T3'.format(dip),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t3-{} from policy-map IPV6-DST-T1'.format(dip),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t3-{} from policy-map IPV6-DST-T2'.format(dip),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t3-{} then policy-map IPV6-DST-T3'.format(dip),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t3-{} then next term'.format(dip),

                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t4-{} from flexible-match-mask mask-in-hex 0xffffffff'.format(dip),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t4-{} from flexible-match-mask prefix {}'.format(dip, split_val_dst[3]),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t4-{} from flexible-match-mask flexible-mask-name V6-IN-V6-INNER-DST-IP-T4'.format(dip),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t4-{} from policy-map IPV6-DST-T1'.format(dip),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t4-{} from policy-map IPV6-DST-T2'.format(dip),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t4-{} from policy-map IPV6-DST-T3'.format(dip),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t4-{} then policy-map INNER-SRC-PORT'.format(dip),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t4-{} then count v6-in-v6-count-{}'.format(dip, dip),
                'set firewall family inet6 filter gtp-v1-stage4-dest-filter-v6 term ipv6-t4-{} then accept'.format(dip),
                ]
                config = stage2+stage3+stage4
                for add in config:
                    f1.write(add)
                    f1.write('\n')
        f1.close()    
        print("V6 in V6 terms configs saved in file scaled_v6-in-v6_filters_{}_terms".format(terms))

def main():
    if args.BASE:
        config_template()
    if args.TERM:
        scale_term(args.TERM, args.IPTYPE)
    print(50*"=")
    print(" \n Note: please add the input chain configuration directly on respective interfaces \n The below syntax can be used \n set interfaces <interface name> unit <unit number > family inet filter input-chain [gtp-v1-stage1-classify gtp-v1-stage2-filter-teid gtp-v1-stage3-source-filter gtp-v1-stage4-dest-filter ] \n set interfaces <interface name> unit <unit number > family inet6 filter input-chain [gtp-v1-stage1-classify-v6 gtp-v1-stage2-filter-teid-v6 gtp-v1-stage3-source-filter-v6 gtp-v1-stage4-dest-filter-v6]\n")
    print(50*"=")
 
if __name__ == '__main__':
    main()
