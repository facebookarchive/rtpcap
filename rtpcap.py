#!/usr/bin/env python3
# Copyright (c) Facebook, Inc. and its affiliates.

"""rtpcap: RTP Pcap Trace Parser."""

import argparse
import re
import subprocess
import sys


default_values = {
    'debug': 0,
    'dry_run': False,
    'infile': None,
}


def run(command, options, **kwargs):
    env = kwargs.get('env', None)
    stdin = subprocess.PIPE if kwargs.get('stdin', False) else None
    bufsize = kwargs.get('bufsize', 0)
    universal_newlines = kwargs.get('universal_newlines', False)
    default_close_fds = True if sys.platform == 'linux2' else False
    close_fds = kwargs.get('close_fds', default_close_fds)
    shell = type(command) in (type(''), type(u''))
    if options.dry_run:
        return 0, b'stdout', b'stderr'
    p = subprocess.Popen(command, stdin=stdin, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, bufsize=bufsize,
                         universal_newlines=universal_newlines,
                         env=env, close_fds=close_fds, shell=shell)
    # wait for the command to terminate
    if stdin is not None:
        out, err = p.communicate(stdin)
    else:
        out, err = p.communicate()
    returncode = p.returncode
    # clean up
    del p
    # return results
    return returncode, out, err


def parse_file(infile, options):
    print('options: %r' % options)
    # get heavy hitters
    output = analyze_udp_connections(infile, options)
    if not output:
        print('error: no UDP connections in %s' % infile)
        sys.exit(-1)
    if options.debug > 2:
        for d in output:
            print(d)
    conn = output[0]
    if options.debug > 0:
        print('conn is {laddr}:{lport} <-> {raddr}:{rport} proto: {proto} bytes: {tbytes}'.format(**conn))
    # process connection
    prefix = '%s.%s' % (infile, 'conn')
    process_connection(conn, infile, prefix, options)


# get heavy hitters
def analyze_udp_connections(infile, options):
    command = 'tshark -r %s -q -z conv,udp' % infile
    returncode, out, err = run(command, options)
    if returncode != 0:
        print('Cannot run "%s": "%s"' % (command, err))
        sys.exit(-1)
    # parse the output
    return parse_udp_connections(out, options)


def get_addr_proto(addr):
    ipv4_pattern = r'^\d\.\d\.\d\.\d'
    ipv6_pattern = r'^[a-fA-F\d:]+'
    if re.search(ipv4_pattern, addr):
        return 'ip'
    elif re.search(ipv6_pattern, addr):
        return 'ipv6'
    return None


def parse_udp_connections(out, options):
    output = []
    # example: '192.168.1.32:5353          <-> 224.0.0.251:5353                 0         0       8      4276       8      4276     0.560657000         7.6643'
    conn_pattern = (
        r'(?P<laddr>[\da-fA-F\.\:]*):(?P<lport>\d*) *'
        r' <-> '
        r'(?P<raddr>[\da-fA-F\.\:]*):(?P<rport>\d*) *'
        r'(?P<rpkts>\d*) *'
        r'(?P<rbytes>\d*) *'
        r'(?P<lpkts>\d*) *'
        r'(?P<lbytes>\d*) *'
        r'(?P<tpkts>\d*) *'
        r'(?P<tbytes>\d*) *'
        r'(?P<start>[\d\.]*) *'
        r'(?P<duration>[\d\.]*)$'
    )
    for line in out.splitlines():
        line = line.decode('ascii').strip()
        match = re.search(conn_pattern, line)
        if not match:
            continue
        # check the proto
        proto = get_addr_proto(match.group('laddr'))
        if not proto:
            print('error: invalid proto for ip address "%s"' %
                  match.group('laddr'))
            sys.exit(-1)
        d = {'proto': proto}
        d.update(match.groupdict())
        output.append(d)
    return output


# process a single connection
def process_connection(conn, infile, prefix, options):
    # extract full connection
    tshark_filter = '{proto}.addr=={laddr} && udp.port=={lport} && {proto}.addr=={raddr} && udp.port=={rport}'.format(**conn)
    conn_file = '%s.pcap' % prefix
    command = 'tshark -r %s -Y "%s" -w %s' % (infile, tshark_filter, conn_file)
    returncode, out, err = run(command, options)
    if returncode != 0:
        print('Cannot run "%s": "%s"' % (command, err))
        sys.exit(-1)
    ## extract left connection
    #ltshark_filter = '{proto}.src=={laddr} && udp.srcport=={lport} && {proto}.dst=={raddr} && udp.dstport=={rport}'.format(**conn)
    #lconn_file = '%s.src_%s.pcap' % (prefix, conn['laddr'])
    #command = 'tshark -r %s -Y "%s" -w %s' % (infile, ltshark_filter, lconn_file)
    #returncode, out, err = run(command, options)
    #if returncode != 0:
    #    print('Cannot run "%s": "%s"' % (command, err))
    #    sys.exit(-1)
    ## extract right connection
    #rtshark_filter = '{proto}.dst=={laddr} && udp.dstport=={lport} && {proto}.src=={raddr} && udp.srcport=={rport}'.format(**conn)
    #rconn_file = '%s.src_%s.pcap' % (prefix, conn['raddr'])
    #command = 'tshark -r %s -Y "%s" -w %s' % (infile, rtshark_filter, rconn_file)
    #returncode, out, err = run(command, options)
    #if returncode != 0:
    #    print('Cannot run "%s": "%s"' % (command, err))
    #    sys.exit(-1)

    # analyze connections
    lvideo_statistics = analyze_rtp_data(conn_file, conn['laddr'],
                                         conn['lport'], conn['proto'], options)
    dump_video_statistics(lvideo_statistics, conn['laddr'], conn_file)
    rvideo_statistics = analyze_rtp_data(conn_file, conn['raddr'],
                                         conn['rport'], conn['proto'], options)
    dump_video_statistics(rvideo_statistics, conn['raddr'], conn_file)


def get_video_rtp_p_type(p_type_dict, saddr, options):
    # the video p_type is typically the one with the most markers (audio
    # typically has 1 marker, data zero)
    p_type_list = sorted(p_type_dict.items(), key=lambda x: x[1][1],
                         reverse=True)
    video_rtp_p_type = p_type_list[0][0]
    if options.debug > 0:
        for (p_type, (bitrate, markers)) in p_type_list:
            print('# saddr: %s p_type: %s bitrate: %f markers: %i' % (
                saddr, p_type, bitrate, markers))
    return video_rtp_p_type


def analyze_rtp_data(infile, saddr, sport, proto, options):
    ipsrc_field = '%s.src' % proto
    iplen_field = 'ip.len' if proto == 'ip' else 'ipv6.plen'
    command = ('tshark -r %s -d udp.port==%s,rtp '
               '-n -T fields -e frame.number -e frame.time_epoch '
               '-e %s -e %s '
               '-e rtp.p_type -e rtcp.pt -e rtp.seq -e rtp.timestamp '
               '-e rtp.marker' % (infile, sport, ipsrc_field, iplen_field))
    returncode, out, err = run(command, options)
    if returncode != 0:
        print('Cannot run "%s": "%s"' % (command, err))
        sys.exit(-1)
    parsed_pkt_list = parse_rtp_data(out, saddr, options)
    rtp_pkt_list = parsed_pkt_list['rtp']
    # rtcp_pkt_list = parsed_pkt_list['rtcp']
    # process RTP traffic
    # get the video rtp_p_type
    p_type_dict = classify_rtp_payload_types(rtp_pkt_list)
    video_rtp_p_type = get_video_rtp_p_type(p_type_dict, saddr, options)

    # parse video stream
    video_statistics = analyze_video_stream(rtp_pkt_list, video_rtp_p_type,
                                            options)
    return video_statistics


def dump_video_statistics(video_statistics, saddr, conn_file):
    outfile = '%s.src_%s.video.csv' % (conn_file, saddr)
    with open(outfile, 'w') as f:
        f.write('# frame_time_epoch, sec_pkts, sec_bits, sec_frames, '
                'sec_max_frame_pkts, sec_max_frame_bits, sec_rtp_seq_issues, '
                'sec_frame_pkts\n')
        for (frame_time_epoch, sec_pkts, sec_bits, sec_frames,
             sec_max_frame_pkts, sec_max_frame_bits, sec_rtp_seq_issues,
             sec_frame_pkts) in video_statistics:
            f.write('%i,%i,%i,%i,%i,%i,%i,%s\n' % (frame_time_epoch, sec_pkts,
                                                   sec_bits, sec_frames,
                                                   sec_max_frame_pkts,
                                                   sec_max_frame_bits,
                                                   sec_rtp_seq_issues,
                                                   sec_frame_pkts))
    return 0


def analyze_video_stream(rtp_pkt_list, video_rtp_p_type, options):
    statistics = []
    sec_pkts = 0
    sec_bytes = 0
    sec_frames = 0
    sec_max_frame_pkts = 0
    sec_max_frame_bytes = 0
    sec_frame_pkts = []
    sec_rtp_seq_issues = 0
    frame_pkts = 0
    frame_bytes = 0
    sec_frame_time_epoch = -1
    frame_rtp_timestamp = -1
    frame_rtp_seq = -1

    for rtp_pkt in rtp_pkt_list:
        if rtp_pkt['rtp_p_type'] != video_rtp_p_type:
            continue
        if sec_frame_time_epoch == -1:
            sec_frame_time_epoch = rtp_pkt['frame_time_epoch']
        if frame_rtp_timestamp == -1:
            frame_rtp_timestamp = rtp_pkt['rtp_timestamp']
        if frame_rtp_seq == -1:
            frame_rtp_seq = rtp_pkt['rtp_seq'] - 1
        frame_time_epoch = rtp_pkt['frame_time_epoch']
        # check for start of frame
        if frame_pkts == 0:
            frame_rtp_timestamp = rtp_pkt['rtp_timestamp']
        # check the RTP sequence number
        if rtp_pkt['rtp_seq'] != frame_rtp_seq + 1:
            sec_rtp_seq_issues += 1
            if options.debug > 1:
                print('warning: RTP seq number non-consecutive (%i, %i) %r' % (
                      frame_rtp_seq, rtp_pkt['rtp_seq'], rtp_pkt))

        frame_rtp_seq = rtp_pkt['rtp_seq']
        # check the RTP timestamp
        if rtp_pkt['rtp_timestamp'] != frame_rtp_timestamp:
            print('warning: RTP timestamp jump (%i, %i) %r' % (
                  frame_rtp_timestamp, rtp_pkt['rtp_timestamp'], rtp_pkt))
        if frame_time_epoch > sec_frame_time_epoch + 1.0:
            # new second: flush statistics
            statistics.append([frame_time_epoch, sec_pkts, sec_bytes * 8,
                               sec_frames, sec_max_frame_pkts,
                               sec_max_frame_bytes * 8, sec_rtp_seq_issues,
                               ':'.join([str(i) for i in sec_frame_pkts])])
            sec_frame_time_epoch = frame_time_epoch
            sec_bytes = 0
            sec_pkts = 0
            sec_frames = 0
            sec_max_frame_pkts = 0
            sec_max_frame_bytes = 0
            sec_frame_pkts = []
            sec_rtp_seq_issues = 0
        # account for the packet
        sec_pkts += 1
        frame_pkts += 1
        frame_bytes += rtp_pkt['iplen']
        sec_bytes += rtp_pkt['iplen']
        # check for end of frame
        if rtp_pkt['rtp_marker'] == 1:
            # account for the frame
            sec_max_frame_pkts = max(sec_max_frame_pkts, frame_pkts)
            sec_max_frame_bytes = max(sec_max_frame_bytes, frame_bytes)
            sec_frame_pkts.append(frame_pkts)
            frame_pkts = 0
            frame_bytes = 0
            sec_frames += 1
    return statistics


def get_duration_sec(rtp_pkt_list):
    first_frame_time = rtp_pkt_list[0]['frame_time_epoch']
    last_frame_time = rtp_pkt_list[-1]['frame_time_epoch']
    return last_frame_time - first_frame_time


def classify_rtp_payload_types(rtp_pkt_list):
    duration_sec = get_duration_sec(rtp_pkt_list)
    p_type_dict = {}
    num_markers = {}
    for rtp_pkt in rtp_pkt_list:
        rtp_p_type = rtp_pkt['rtp_p_type']
        if rtp_p_type not in p_type_dict:
            p_type_dict[rtp_p_type] = 0
        if rtp_p_type not in num_markers:
            num_markers[rtp_p_type] = 0
        iplen = rtp_pkt['iplen']
        p_type_dict[rtp_p_type] += iplen
        num_markers[rtp_p_type] += rtp_pkt['rtp_marker']
    for rtp_p_type in p_type_dict:
        total_iplen = p_type_dict[rtp_p_type]
        p_type_dict[rtp_p_type] = [total_iplen * 8. / duration_sec,
                                   num_markers[rtp_p_type]]
    return p_type_dict


def parse_rtp_data(out, saddr, options):
    output = {
        'rtp': [],
        'rtcp': [],
    }
    # example (rtp): '1\t1584373727.996807000\t2601:647:4300:f039:e97a:e051:b8a8:a4da\t103\t\t2303\t1266375689\t0'
    # example (rtcp): '3\t1584373728.001695000\t2601:647:4300:f039:e97a:e051:b8a8:a4da\t\t205'
    pkt_pattern = (
        r'(?P<frame_number>\d+)\t'
        r'(?P<frame_time_epoch>[\d\.]+)\t'
        r'(?P<ipsrc>[\da-fA-F\.\:]+)\t'
        r'(?P<iplen>\d+)\t'
        r'(?P<rtp_p_type>\d*)\t'  # optional
        r'(?P<rtcp_pt>\d*)\t*'  # optional
        r'(?P<rtp_seq>\d*)\t*'  # optional
        r'(?P<rtp_timestamp>\d*)\t*'  # optional
        r'(?P<rtp_marker>\d*)'  # optional
    )
    for line in out.splitlines():
        line = line.decode('ascii').strip()
        match = re.search(pkt_pattern, line)
        if not match:
            # STUN, DTLS, etc.
            if options.debug > 2:
                print('warning: invalid RTP line: "%s"' % line)
            continue
        # filter the packet
        if match.group('ipsrc') != saddr:
            continue
        # check the protocol
        protocol = 'rtp' if match.group('rtp_p_type') else 'rtcp'
        entry = match.groupdict()
        # massage values
        entry['frame_number'] = int(entry['frame_number'])
        entry['frame_time_epoch'] = float(entry['frame_time_epoch'])
        entry['iplen'] = int(entry['iplen'])
        if protocol == 'rtp':
            entry['rtp_p_type'] = int(entry['rtp_p_type'])
            del entry['rtcp_pt']
            entry['rtp_seq'] = int(entry['rtp_seq'])
            entry['rtp_timestamp'] = int(entry['rtp_timestamp'])
            entry['rtp_marker'] = int(entry['rtp_marker'])
        elif protocol == 'rtcp':
            del entry['rtp_p_type']
            entry['rtcp_pt'] = int(entry['rtcp_pt'])
            del entry['rtp_seq']
            del entry['rtp_timestamp']
            del entry['rtp_marker']
        output[protocol].append(entry)
    return output


def get_options(argv):
    """Generic option parser.

    Args:
        argv: list containing arguments

    Returns:
        Namespace - An argparse.ArgumentParser-generated option object
    """
    # init parser
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-d', '--debug', action='count',
                        dest='debug', default=default_values['debug'],
                        help='Increase verbosity (multiple times for more)',)
    parser.add_argument('--quiet', action='store_const',
                        dest='debug', const=-1,
                        help='Zero verbosity',)
    parser.add_argument('-D', '--dry-run', action='store_true',
                        dest='dry_run', default=default_values['dry_run'],
                        help='Dry run',)
    parser.add_argument('infile', type=str,
                        default=default_values['infile'],
                        metavar='input-file',
                        help='input file',)
    # do the parsing
    options = parser.parse_args(argv[1:])
    return options


def main(argv):
    # parse options
    options = get_options(argv)
    # do something
    parse_file(options.infile, options)


if __name__ == '__main__':
    # at least the CLI program name: (CLI) execution
    main(sys.argv)
