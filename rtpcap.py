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
    'analysis_type': 'all',
    'filter': None,
    'infile': None,
}


IPV4_PATTERN = r'\d+\.\d+\.\d+\.\d+'
IPV6_PATTERN = r'[a-fA-F\d:]+'
IP_PATTERN = r'[a-fA-F\d:\.]+'

ANALYSIS_TYPES = {
    'video',
    'audio-jitter',
    'audio-ploss',
    'all',
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
    udp_connections = analyze_udp_connections(infile, options)
    if not udp_connections:
        print('error: no UDP connections in %s' % infile)
        sys.exit(-1)
    if options.debug > 2:
        for d in udp_connections:
            print(d)
    conn = udp_connections[0]
    if options.debug > 0:
        print('main_conn {{ left: {laddr}:{lport} right: {raddr}:{rport} '
              'proto: {proto} bytes: {tbytes} packets: {tpkts} }}'.format(
                  **conn))
    # process connection
    prefix = '%s.%s' % (infile, 'conn')
    process_connection(infile, udp_connections, conn, prefix, options)


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
    if re.search(IPV4_PATTERN, addr):
        return 'ip'
    elif re.search(IPV6_PATTERN, addr):
        return 'ipv6'
    return None


def parse_udp_connections(out, options):
    udp_connections = []
    # example: '1.1.1.1:1111 <-> 2.2.2.2:2222 0 0 8 4276 8 4276 0.56065 7.6643'
    conn_pattern = (
        r'(?P<laddr>' + IP_PATTERN + r'):(?P<lport>\d*) *'
        r' <-> '
        r'(?P<raddr>' + IP_PATTERN + r'):(?P<rport>\d*) *'
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
        udp_connections.append(d)
    return udp_connections


# process a single connection
def process_connection(infile, udp_connections, conn, prefix, options):
    # create filter for full connection
    conn_filter = '{proto}.addr=={laddr} && udp.port=={lport} && {proto}.addr=={raddr} && udp.port=={rport}'.format(**conn)
    if options.filter is not None:
        conn_filter += ' && ' + options.filter

    parsed_rtp_list = analyze_rtp_data(infile, conn_filter, conn['lport'],
                                       conn['proto'], options)
    # filter connection data

    if options.debug > 0:
        for ip_src in parsed_rtp_list.keys():
            for rtp_ssrc in parsed_rtp_list[ip_src].keys():
                for rtp_p_type in parsed_rtp_list[ip_src][rtp_ssrc].keys():
                    ip_len = sum(d['ip_len'] for d in
                                 parsed_rtp_list[ip_src][rtp_ssrc][rtp_p_type])
                    pkts = len(parsed_rtp_list[ip_src][rtp_ssrc][rtp_p_type])
                    print('ip_src: %s rtp_ssrc: %s rtp_p_type: %i '
                          'ip_len: %i pkts: %i' % (
                              ip_src, rtp_ssrc, rtp_p_type, ip_len, pkts))

    ## analyze connections
    #if options.analysis_type == 'video':
    #    rtp_pkt_list = analyze_rtp_data(conn_file, conn['laddr'],
    #                                    conn['lport'], conn['proto'], options)
    #    # process RTP traffic
    #    # get the video rtp_p_type
    #    p_type_dict = classify_rtp_payload_types(rtp_pkt_list)
    #    video_rtp_p_type = get_video_rtp_p_type(p_type_dict, saddr, options)
    #    # parse video stream
    #    lvideo_statistics = analyze_video_stream(rtp_pkt_list, video_rtp_p_type,
    #                                             options)
    #    dump_video_statistics(lvideo_statistics, conn['laddr'], conn_file)

    #    rtp_pkt_list = analyze_rtp_data(conn_file, conn['raddr'],
    #                                    conn['rport'], conn['proto'], options)
    #    # process RTP traffic
    #    # get the video rtp_p_type
    #    p_type_dict = classify_rtp_payload_types(rtp_pkt_list)
    #    video_rtp_p_type = get_video_rtp_p_type(p_type_dict, saddr, options)

    #    # parse video stream
    #    rvideo_statistics = analyze_video_stream(rtp_pkt_list, video_rtp_p_type,
    #                                             options)
    #    dump_video_statistics(rvideo_statistics, conn['raddr'], conn_file)

    for ip_src in parsed_rtp_list.keys():
        for rtp_ssrc in parsed_rtp_list[ip_src].keys():
            for rtp_p_type in parsed_rtp_list[ip_src][rtp_ssrc].keys():
                if options.analysis_type == 'audio-jitter':
                    analyze_audio_jitter(infile, parsed_rtp_list, ip_src,
                                         rtp_ssrc, rtp_p_type, options)
                elif options.analysis_type == 'audio-ploss':
                    analyze_audio_ploss(infile, parsed_rtp_list, ip_src,
                                        rtp_ssrc, rtp_p_type, options)


def analyze_audio_jitter(prefix, parsed_rtp_list, ip_src, rtp_ssrc, rtp_p_type,
                         options):
    output_file = '%s.audio.jitter.ip_src_%s.rtp_ssrc_%s.rtp_p_type_%i.csv' % (
        prefix, ip_src, rtp_ssrc, rtp_p_type)
    with open(output_file, 'w') as f:
        delta_list = []
        last_frame_time_relative = None
        for pkt in parsed_rtp_list[ip_src][rtp_ssrc][rtp_p_type]:
            if last_frame_time_relative is not None:
                delta = pkt['frame_time_relative'] - last_frame_time_relative
                delta_list.append([pkt['frame_time_relative'], delta])
            last_frame_time_relative = pkt['frame_time_relative']
        total_delta = sum(delta for _, delta in delta_list)
        samples = len(delta_list)
        average_delta = total_delta / samples
        for frame_time_relative, delta in delta_list:
            f.write('%f,%f,%f\n' % (frame_time_relative, delta, average_delta))


# returns a number between [-32k, 32k)
def rtp_ploss_diff(a, b):
    mod = (a - b) % 65536
    if mod >= 32768:
        mod -= 65536
    return mod


def analyze_audio_ploss(prefix, parsed_rtp_list, ip_src, rtp_ssrc, rtp_p_type,
                         options):
    output_file = '%s.audio.ploss.ip_src_%s.rtp_ssrc_%s.rtp_p_type_%i.csv' % (
        prefix, ip_src, rtp_ssrc, rtp_p_type)
    with open(output_file, 'w') as f:
        delta_list = []
        last_rtp_seq = -1
        for pkt in parsed_rtp_list[ip_src][rtp_ssrc][rtp_p_type]:
            if last_rtp_seq != -1:
                delta = rtp_ploss_diff(pkt['rtp_seq'], last_rtp_seq)
                delta_list.append([pkt['frame_time_relative'], delta])
            last_rtp_seq = pkt['rtp_seq']
        for frame_time_relative, delta in delta_list:
            f.write('%f,%i\n' % (frame_time_relative, delta))


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


def analyze_rtp_data(infile, conn_filter, sport, proto, options):
    ip_src_field = '%s.src' % proto
    ip_len_field = 'ip.len' if proto == 'ip' else 'ipv6.plen'
    command = ('tshark -r %s '
               '-d udp.port==%s,rtp '
               '-Y "%s" '
               '-n -T fields -e frame.number '
               '-e frame.time_epoch -e frame.time_relative '
               '-e %s -e %s '
               '-e rtp.p_type -e rtcp.pt -e rtp.ssrc -e rtp.seq '
               '-e rtp.timestamp -e rtp.marker' % (
                   infile, sport, conn_filter, ip_src_field, ip_len_field))
    returncode, out, err = run(command, options)
    if returncode != 0:
        print('Cannot run "%s": "%s"' % (command, err))
        sys.exit(-1)
    parsed_rtp_list, _ = parse_rtp_data(out, options)
    return parsed_rtp_list


def dump_video_statistics(video_statistics, saddr, conn_file):
    outfile = '%s.src_%s.video.csv' % (conn_file, saddr)
    with open(outfile, 'w') as f:
        f.write('# frame_time_epoch, frame_time_relative, '
                'sec_pkts, sec_bits, sec_frames, '
                'sec_max_frame_pkts, sec_max_frame_bits, sec_rtp_seq_issues, '
                'sec_frame_pkts\n')
        for (frame_time_epoch, frame_time_relative,
             sec_pkts, sec_bits, sec_frames,
             sec_max_frame_pkts, sec_max_frame_bits, sec_rtp_seq_issues,
             sec_frame_pkts) in video_statistics:
            f.write('%f.%f,%i,%i,%i,%i,%i,%i,%s\n' % (
                frame_time_epoch, frame_time_relative,
                sec_pkts, sec_bits, sec_frames,
                sec_max_frame_pkts, sec_max_frame_bits,
                sec_rtp_seq_issues, sec_frame_pkts))
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
        frame_bytes += rtp_pkt['ip_len']
        sec_bytes += rtp_pkt['ip_len']
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
        ip_len = rtp_pkt['ip_len']
        p_type_dict[rtp_p_type] += ip_len
        num_markers[rtp_p_type] += rtp_pkt['rtp_marker']
    for rtp_p_type in p_type_dict:
        total_ip_len = p_type_dict[rtp_p_type]
        p_type_dict[rtp_p_type] = [total_ip_len * 8. / duration_sec,
                                   num_markers[rtp_p_type]]
    return p_type_dict


def parse_rtp_data(out, options):
    parsed_rtp_list = {}
    parsed_rtcp_list = {}
    # example (rtp): '2\t1584723835.328870000\t0.0\t2a03:2880:f231:cd:face:b00c:0:6443\t1135\t98\t\t0xd7346929\t27012\t1122654371\t0'
    # example (rtcp): '3\t1584373728.001695000\t0.00001\t2601:647:4300:f039:e97a:e051:b8a8:a4da\t\t205'
    pkt_pattern = (
        r'(?P<frame_number>\d+)\t'
        r'(?P<frame_time_epoch>[\d\.]+)\t'
        r'(?P<frame_time_relative>[\d\.]+)\t'
        r'(?P<ip_src>' + IP_PATTERN + r')\t'
        r'(?P<ip_len>\d+)\t'
        r'(?P<rtp_p_type>\d*)\t'  # optional
        r'(?P<rtcp_pt>\d*)\t*'  # optional
        r'(?P<rtp_ssrc>0x[\da-fA-F]*)\t*'  # optional
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
        # check the protocol
        protocol = 'rtp' if match.group('rtp_p_type') else 'rtcp'
        entry = match.groupdict()
        # massage values
        entry['frame_number'] = int(entry['frame_number'])
        entry['frame_time_epoch'] = float(entry['frame_time_epoch'])
        entry['frame_time_relative'] = float(entry['frame_time_relative'])
        # entry['ip_src'] = entry['ip_src']
        ip_src = entry['ip_src']
        entry['ip_len'] = int(entry['ip_len'])
        if protocol == 'rtp':
            entry['rtp_p_type'] = int(entry['rtp_p_type'])
            rtp_p_type = entry['rtp_p_type']
            del entry['rtcp_pt']
            entry['rtp_ssrc'] = int(entry['rtp_ssrc'], 16)
            rtp_ssrc = '%08x' % entry['rtp_ssrc']
            entry['rtp_seq'] = int(entry['rtp_seq'])
            entry['rtp_timestamp'] = int(entry['rtp_timestamp'])
            entry['rtp_marker'] = int(entry['rtp_marker'])
            if ip_src not in parsed_rtp_list:
                parsed_rtp_list[ip_src] = {}
            if rtp_ssrc not in parsed_rtp_list[ip_src]:
                parsed_rtp_list[ip_src][rtp_ssrc] = {}
            if rtp_p_type not in parsed_rtp_list[ip_src][rtp_ssrc]:
                parsed_rtp_list[ip_src][rtp_ssrc][rtp_p_type] = []
            parsed_rtp_list[ip_src][rtp_ssrc][rtp_p_type].append(entry)
        elif protocol == 'rtcp':
            del entry['rtp_p_type']
            entry['rtcp_pt'] = int(entry['rtcp_pt'])
            del entry['rtp_ssrc']
            del entry['rtp_seq']
            del entry['rtp_timestamp']
            del entry['rtp_marker']
            if ip_src not in parsed_rtcp_list:
                parsed_rtcp_list[ip_src] = []
            parsed_rtcp_list[ip_src].append(entry)
    return parsed_rtp_list, parsed_rtcp_list


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
    parser.add_argument('-a', '--analysis', action='store', type=str,
                        dest='analysis_type',
                        default=default_values['analysis_type'],
                        choices=ANALYSIS_TYPES,
                        metavar='ANALYSIS_TYPE',
                        help='analysis type %r' % ANALYSIS_TYPES,)
    parser.add_argument('--audio-jitter', action='store_const',
                        dest='analysis_type', const='audio-jitter',
                        metavar='ANALYSIS_TYPE',
                        help='analysis type: audio-jitter',)
    parser.add_argument('--audio-ploss', action='store_const',
                        dest='analysis_type', const='audio-ploss',
                        metavar='ANALYSIS_TYPE',
                        help='analysis type: audio-ploss',)
    parser.add_argument('--filter', action='store', type=str,
                        dest='filter',
                        default=default_values['filter'],
                        metavar='FILTER',
                        help='filter',)
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
