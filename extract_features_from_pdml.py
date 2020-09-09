#!/usr/bin/env python

from xml.etree.cElementTree import iterparse
from sys import stdin, stdout
from argparse import ArgumentParser
from csv import writer, QUOTE_ALL


if __name__ == '__main__':
    # Argument handling
    parser = ArgumentParser(description="")
    parser.add_argument("--features", type=str, required=True, nargs='+',
                        help="List of features.")
    args = parser.parse_args()

    # set up csv output and write header
    csv = writer(stdout, quoting=QUOTE_ALL)
    csv.writerow(args.features)

    # parse tshark's XML stream
    for event, elem in iterparse(stdin, events=('start', 'end')):
        if event == 'start':
            # detect start of packet
            if elem.tag == 'packet':
                pkt = dict()
                for feature in args.features:
                    pkt[feature] = ''
                elem.clear()
                continue
            # extract feature
            if elem.tag == 'field' and elem.attrib['name'] in args.features:
                if elem.attrib['name'] == 'timestamp':
                    pkt[elem.attrib['name']] = elem.attrib['value']
                else:
                    pkt[elem.attrib['name']] = elem.attrib['show']
                elem.clear()
                continue
        # detect end of packet and write output
        if elem.tag == 'packet' and event == 'end':
            if pkt['ip.src'] and pkt['ip.dst']:
                csv.writerow([pkt[feature] for feature in args.features])
            elem.clear()
            continue
        # clear memory
        elem.clear()
