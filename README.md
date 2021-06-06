# Generate scaled GTP-U packets with variable TEID , Source IP and Destination IP addresses 
This program helps to generate a scaled GTP packet configuration. The output can be written into a pcap as well

## Usage
```
python gtp_v1_scale.py -ver v1 -nteid 1000 -npkts 10 -write 1000_teid.pcap
```

# Generate scaled flex filter configuration for matching TEIDs
Juniper MX routers can filter GTP packet using flex filter offsets. This gives us an ability to run firewall filters and match on GTP TEID header as well as the inner IP headers for various combinations such as v4 in v4, v4 in v6, v6 in v4 and v6 in v6

Generate Junos set configuration for GTPv1 and v2 filtering using flex filters which can be used on vMX/MX.
Usage: python config_gtp_flex.py -term <number of unique teid/src/dst ip> -iptype <v4inv4/v4inv6/v6inv4/v6inv6>
add -base optionally to generate the common base configuration

In order to create a scaled config, /32 prefixes for IPv4 and /128 prefixes for IPv6 are used in the filter prefix matches
This allows to ensure max scale can be tested.
The number teid terms creates unique TEID values. The source prefix and destination prefixes are also unique for each TEID.
we increment by "1" for every TEID so that we can easily track during testing the number of packet matches.
Starting TEID Range cannot be "1" because this is used in the base template config and should be the first term hit in the filter

## Usage

```
python config_gtp_flex.py -term 10 -base -iptype v4inv4
python config_gtp_flex.py -term 10 -iptype v4inv6
python config_gtp_flex.py -term 10 -iptype v6inv6
python config_gtp_flex.py -term 10 -iptype v6inv4
```
