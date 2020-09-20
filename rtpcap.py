#!/usr/bin/env python3
# Copyright (c) Facebook, Inc. and its affiliates.

"""rtpcap: RTP Pcap Trace Parser."""

import argparse
import hashlib
import re
import subprocess
import sys


default_values = {
    'debug': 0,
    'dry_run': False,
    'connections': 1,
    'analysis_type': 'all',
    'period_sec': 1.0,
    'filter': None,
    'infile': None,
}


IPV4_PATTERN = r'\d+\.\d+\.\d+\.\d+'
IPV6_PATTERN = r'[a-fA-F\d:]+'
IP_PATTERN = r'[a-fA-F\d:\.]+'


# there are 3 types of analysis:
# 1. per-packet: one entry per RTP packet
# 2. per-frame: one entry for all RTP packets with the same timestamp
# (video only)
# 3. per-time: one entry for all RTP packets in the same period (`period_sec`)
ANALYSIS_TYPES = {
    'network-time',
    'audio-packet',
    'video-time',
    'video-frame',
    'video-packet',
    'all',
}

OUTPUT_HEADERS = {}


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
    for i in range(min(options.connections, len(udp_connections))):
        conn = udp_connections[i]
        if options.debug > 0:
            print('connection {{ left: {laddr}:{lport} '
                  'right: {raddr}:{rport} proto: {proto} bytes: {tbytes} '
                  'packets: {tpkts} }}'.format(**conn))
        # process connection
        prefix = '%s.%s' % (infile, 'conn')
        process_connection(infile, conn, prefix, options)


def tshark_error_check(returncode, out, err, command):
    if (returncode == 2 and
            b'have been cut short in the middle of a packet' in err):
        # we are ok with pcap traces cut short
        pass
    elif returncode != 0:
        print('Cannot run "%s": "%s"' % (command, err))
        sys.exit(-1)


# get heavy hitters
def analyze_udp_connections(infile, options):
    command = 'tshark -r %s -q -z conv,udp' % infile
    returncode, out, err = run(command, options)
    tshark_error_check(returncode, out, err, command)
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


def get_rtp_p_type_list(parsed_rtp_list):
    rtp_p_type_list = list({pkt['rtp_p_type'] for pkt in parsed_rtp_list})
    return rtp_p_type_list


def print_process_connection_information(parsed_rtp_list):
    for ip_src in parsed_rtp_list.keys():
        # sort ssrc lines by payload type first, alphabetically second
        rtp_ssrc_list = list(parsed_rtp_list[ip_src].keys())
        rtp_ssrc_list = sorted(rtp_ssrc_list)
        rtp_ssrc_list = sorted(
            rtp_ssrc_list,
            key=lambda rtp_ssrc: get_rtp_p_type_list(
                parsed_rtp_list[ip_src][rtp_ssrc])[0])
        for rtp_ssrc in rtp_ssrc_list:
            ip_len = sum(d['ip_len'] for d in
                         parsed_rtp_list[ip_src][rtp_ssrc])
            duration = (parsed_rtp_list[ip_src][rtp_ssrc][-1]
                        ['frame_time_epoch'] -
                        parsed_rtp_list[ip_src][rtp_ssrc][0]
                        ['frame_time_epoch'])
            pkts = len(parsed_rtp_list[ip_src][rtp_ssrc])
            rtp_p_type_list = get_rtp_p_type_list(
                parsed_rtp_list[ip_src][rtp_ssrc])
            print('ip_src: %s rtp_ssrc: %s rtp_p_type_list: %s '
                  'ip_len: %i pkts: %i duration: %f' % (
                      ip_src, rtp_ssrc, rtp_p_type_list, ip_len, pkts,
                      duration))


# process a single connection
def process_connection(infile, conn, prefix, options):
    # create filter for full connection
    conn_filter = ('{proto}.addr=={laddr} && udp.port=={lport} && '
                   '{proto}.addr=={raddr} && udp.port=={rport}'.format(**conn))
    if options.filter is not None:
        conn_filter += ' && ' + options.filter

    parsed_rtp_list = analyze_rtp_data(infile, conn_filter, conn['lport'],
                                       conn['proto'], options)
    # filter connection data

    if options.debug > 0:
        print_process_connection_information(parsed_rtp_list)

    # analyze connections
    # if options.analysis_type == 'video':
    #    rtp_pkt_list = analyze_rtp_data(conn_file, conn['laddr'],
    #                                    conn['lport'], conn['proto'], options)
    #    # process RTP traffic
    #    # get the video rtp_p_type
    #    p_type_dict = classify_rtp_payload_types(rtp_pkt_list)
    #    video_rtp_p_type = get_video_rtp_p_type(p_type_dict, saddr, options)
    #    # parse video stream
    #    lvideo_statistics = analyze_video_stream(rtp_pkt_list,
    #                                             video_rtp_p_type,
    #                                             options)
    #    dump_video_statistics(lvideo_statistics, conn['laddr'], conn_file)

    #    rtp_pkt_list = analyze_rtp_data(conn_file, conn['raddr'],
    #                                    conn['rport'], conn['proto'], options)
    #    # process RTP traffic
    #    # get the video rtp_p_type
    #    p_type_dict = classify_rtp_payload_types(rtp_pkt_list)
    #    video_rtp_p_type = get_video_rtp_p_type(p_type_dict, saddr, options)

    #    # parse video stream
    #    rvideo_statistics = analyze_video_stream(rtp_pkt_list,
    #                                             video_rtp_p_type,
    #                                             options)
    #    dump_video_statistics(rvideo_statistics, conn['raddr'], conn_file)

    for ip_src in parsed_rtp_list.keys():
        for rtp_ssrc in parsed_rtp_list[ip_src].keys():
            # 1. calculate output data
            if options.analysis_type == 'network-time':
                out_data = analyze_network_time(
                    parsed_rtp_list, ip_src, rtp_ssrc, options.period_sec)
            elif options.analysis_type == 'audio-packet':
                out_data = analyze_audio_packet(
                    parsed_rtp_list, ip_src, rtp_ssrc)
            elif options.analysis_type == 'video-time':
                out_data = analyze_video_time(
                    parsed_rtp_list, ip_src, rtp_ssrc, options.period_sec)
            elif options.analysis_type == 'video-frame':
                out_data = analyze_video_frame(
                    parsed_rtp_list, ip_src, rtp_ssrc)
            elif options.analysis_type == 'video-packet':
                out_data = analyze_video_packet(
                    parsed_rtp_list, ip_src, rtp_ssrc)
            # 2. dump data
            output_file = '%s.%s.ip_src_%s.rtp_ssrc_%s.csv' % (
                infile, options.analysis_type, ip_src, rtp_ssrc)
            with open(output_file, 'w') as f:
                out_hdr = OUTPUT_HEADERS[options.analysis_type]
                line_format = '%s\n' % ','.join(['%s'] * len(out_hdr))
                header = '# ' + line_format
                f.write(header % out_hdr)
                for entry in out_data:
                    f.write(line_format % tuple(entry))


OUTPUT_HEADERS['audio-packet'] = (
    'frame_time_relative', 'frame_time_epoch', 'delta_time', 'ip_len',
    'rtp_seq', 'delta_rtp_seq', 'dup', 'rtp_ext_rfc5285_data',
)


def analyze_audio_packet(parsed_rtp_list, ip_src, rtp_ssrc):
    # initialization
    out_data = []
    last_frame_time_relative = None
    last_rtp_seq = None
    # list of packet hashes
    pkt_hash_set = set()
    for pkt in parsed_rtp_list[ip_src][rtp_ssrc]:
        if last_frame_time_relative is None:
            last_frame_time_relative = pkt['frame_time_relative']
            last_rtp_seq = pkt['rtp_seq']
        # account for current packet
        # check for dups (whether we have seen the packet already)
        m = hashlib.md5()
        pkt_id = '%s:%s:%s' % (pkt['rtp_p_type'], pkt['rtp_seq'],
                               pkt['rtp_timestamp'])
        m.update(pkt_id.encode('utf-8'))
        pkt_hash = m.hexdigest()
        is_dup = pkt_hash in pkt_hash_set
        if not is_dup:
            pkt_hash_set.add(pkt_hash)
        delta_time = pkt['frame_time_relative'] - last_frame_time_relative
        delta_rtp_seq = rtp_ploss_diff(pkt['rtp_seq'], last_rtp_seq)
        out_data.append([pkt['frame_time_relative'],
                         pkt['frame_time_epoch'],
                         delta_time,
                         pkt['ip_len'],
                         pkt['rtp_seq'],
                         delta_rtp_seq,
                         int(is_dup),
                         pkt['rtp_ext_rfc5285_data']])
        # update last values (frame time and RTP seq number (on non-dups))
        last_frame_time_relative = pkt['frame_time_relative']
        if not is_dup:
            last_rtp_seq = pkt['rtp_seq']
    return out_data


# returns a number between [-32k, 32k)
def rtp_ploss_diff(a, b):
    mod = (a - b) % 65536
    if mod >= 32768:
        mod -= 65536
    return mod


# returns a number between [-32768, 32767]
def rtp_seq_delta(rtp_seq1, rtp_seq2):
    delta = rtp_seq1 - rtp_seq2
    while delta > 32767:
        delta -= 65536
    while delta < -32768:
        delta += 65536
    return delta


# compares two RTP sequences, rtp_seq1 and rtp_seq2, and returns an integer
# less than, equal to, or greater than zero if rtp_seq1 is found,
# respectively, to be less than, to match, or be greater than rtp_seq2
# (considering mod 2**16 math).
def rtp_seq_cmp(rtp_seq1, rtp_seq2):
    return rtp_seq_delta(rtp_seq1, rtp_seq2)


# compares two RTP sequences, rtp_seq1 and rtp_seq2, and returns the greater
# one
def rtp_seq_get_max(rtp_seq1, rtp_seq2):
    if rtp_seq2 is None:
        return rtp_seq1
    if rtp_seq1 is None:
        return rtp_seq2
    return rtp_seq1 if (rtp_seq_cmp(rtp_seq2, rtp_seq1) < 0) else rtp_seq2


def rtp_seq_get_min(rtp_seq1, rtp_seq2):
    if rtp_seq2 is None:
        return rtp_seq1
    if rtp_seq1 is None:
        return rtp_seq2
    return rtp_seq2 if (rtp_seq_cmp(rtp_seq2, rtp_seq1) < 0) else rtp_seq1


# estimates the number of packet losses (ploss), reorderings (porder),
# and duplicates (pdups) of a list of RTP sequence numbers. Returns
# {ploss, porder, pdups, rtp_seq_max}, where `rtp_seq_max` is the highest
# rtp sequence number see so far.
# Input also includes the previous highest rtp sequence number (`rtp_seq_prev`)
#
# Algorithm explanation
# * run through the `rtp_seq_list` calculating the deltas between each
#   value and the previous value (use `rtp_seq_prev` for the first value
#   in the list)
#   * add up the deltas (into `total_delta`), and write up the number of
#     negative deltas
#   * keep the max value at all times
# * when done, `porder` is the number of negative deltas, while ploss is
#   `rtp_seq_max` - `rtp_seq_min` - len(set(rtp_seq_list))
def get_packets_loss_and_out_of_order(rtp_seq_prev, rtp_seq_list):
    if len(rtp_seq_list) == 0:
        return 0, 0, 0, rtp_seq_prev
    # finding duplicates is easy
    if rtp_seq_prev is None:
        full_list = rtp_seq_list
    else:
        full_list = [rtp_seq_prev, ] + rtp_seq_list
    pdups = len(full_list) - len(set(full_list))
    # convert full_list in deltas
    total_delta = 0
    num_negative_delta = 0
    rtp_seq_prev = full_list[0]
    rtp_seq_min = rtp_seq_prev
    rtp_seq_max = rtp_seq_prev
    for rtp_seq in full_list[1:]:
        rtp_seq_min = rtp_seq_get_min(rtp_seq, rtp_seq_min)
        rtp_seq_max = rtp_seq_get_max(rtp_seq, rtp_seq_max)
        delta = rtp_seq_delta(rtp_seq, rtp_seq_prev)
        total_delta += delta
        if delta < 0:
            num_negative_delta += 1
        rtp_seq_prev = rtp_seq
    ploss = rtp_seq_max - rtp_seq_min - len(set(full_list)) + 1
    porder = num_negative_delta
    return ploss, porder, pdups, rtp_seq_max


OUTPUT_HEADERS['network-time'] = (
    'frame_time_relative', 'frame_time_epoch', 'pkts', 'ploss', 'porder',
    'pdups', 'bytes_last_interval', 'bitrate_last_interval',
    'rtp_seq_list', 'rtp_timestamp_list',
)


def analyze_network_time(parsed_rtp_list, ip_src, rtp_ssrc, period_sec):
    # initialization
    out_data = []
    last_frame_time_relative = None
    last_frame_time_epoch = None
    cum_pkts = 0
    cum_bytes = 0
    rtp_seq_list = []
    rtp_seq_list_last_rtp_seq = None
    rtp_timestamp_list = []
    for pkt in parsed_rtp_list[ip_src][rtp_ssrc]:
        if last_frame_time_relative is None:
            last_frame_time_relative = pkt['frame_time_relative']
            last_frame_time_epoch = pkt['frame_time_epoch']
        if pkt['frame_time_relative'] > (last_frame_time_relative +
                                         period_sec):
            ploss, porder, pdups, rtp_seq_list_last_rtp_seq = (
                get_packets_loss_and_out_of_order(rtp_seq_list_last_rtp_seq,
                                                  rtp_seq_list))
            out_data.append([last_frame_time_relative,
                             last_frame_time_epoch,
                             cum_pkts,
                             ploss,
                             porder,
                             pdups,
                             cum_bytes,
                             int(cum_bytes * 8 / period_sec),
                             ':'.join([str(i) for i in rtp_seq_list]),
                             ':'.join([str(i) for i in rtp_timestamp_list])])
            cum_pkts = 0
            cum_bytes = 0
            rtp_seq_list_last_rtp_seq = rtp_seq_list[-1]
            rtp_seq_list = []
            rtp_timestamp_list = []
            # insert zeroes where no data is present
            delta_time = pkt['frame_time_relative'] - last_frame_time_relative
            zero_elements = int((delta_time - period_sec) / period_sec)
            for _i in range(zero_elements):
                last_frame_time_relative += period_sec
                last_frame_time_epoch += period_sec
                out_data.append([last_frame_time_relative,
                                 last_frame_time_epoch,
                                 0,
                                 0,
                                 0,
                                 0,
                                 0,
                                 0,
                                 '',
                                 ''])

            last_frame_time_relative += period_sec
            last_frame_time_epoch += period_sec
        # account for current packet
        cum_pkts += 1
        cum_bytes += pkt['ip_len']
        rtp_seq_list.append(pkt['rtp_seq'])
        rtp_timestamp_list.append(pkt['rtp_timestamp'])

    # flush data
    ploss, porder, pdups, rtp_seq_list_last_rtp_seq = (
        get_packets_loss_and_out_of_order(rtp_seq_list_last_rtp_seq,
                                          rtp_seq_list))
    out_data.append([last_frame_time_relative,
                     last_frame_time_epoch,
                     cum_pkts,
                     ploss,
                     porder,
                     pdups,
                     cum_bytes,
                     int(cum_bytes * 8 / period_sec),
                     ':'.join([str(i) for i in rtp_seq_list]),
                     ':'.join([str(i) for i in rtp_timestamp_list])])
    return out_data


OUTPUT_HEADERS['video-time'] = (
    'frame_time_relative', 'frame_time_epoch',
    'frames_last_interval', 'framerate_last_interval',
    'packets_last_interval', 'packetrate_last_interval',
    'bytes_last_interval', 'bitrate_last_interval',
)


def analyze_video_time(parsed_rtp_list, ip_src, rtp_ssrc, period_sec):
    # initialization
    out_data = []
    last_frame_time_relative = None
    last_frame_time_epoch = None
    cum_frames = 0
    cum_pkts = 0
    cum_bytes = 0
    last_rtp_timestamp = None
    for pkt in parsed_rtp_list[ip_src][rtp_ssrc]:
        if last_frame_time_relative is None:
            last_frame_time_relative = pkt['frame_time_relative']
            last_frame_time_epoch = pkt['frame_time_epoch']
            last_rtp_timestamp = pkt['rtp_timestamp']
        if (pkt['frame_time_relative'] >
                (last_frame_time_relative + period_sec)):
            out_data.append([last_frame_time_relative,
                             last_frame_time_epoch,
                             cum_frames,
                             cum_frames / period_sec,
                             cum_pkts,
                             cum_pkts / period_sec,
                             cum_bytes,
                             int(cum_bytes * 8 / period_sec)])
            cum_frames = 0
            cum_pkts = 0
            cum_bytes = 0
            # insert zeroes where no data is present
            delta_time = pkt['frame_time_relative'] - last_frame_time_relative
            zero_elements = int((delta_time - period_sec) / period_sec)
            for i in range(zero_elements):
                time_delta = (i + 1) * period_sec
                out_data.append([last_frame_time_relative + time_delta,
                                 last_frame_time_epoch + time_delta,
                                 0,
                                 0,
                                 0,
                                 0,
                                 0,
                                 0])

            last_frame_time_relative = pkt['frame_time_relative']
            last_frame_time_epoch = pkt['frame_time_epoch']
        # account for current packet
        if pkt['rtp_timestamp'] > last_rtp_timestamp:
            # new frame
            cum_frames += 1
            last_rtp_timestamp = pkt['rtp_timestamp']
        cum_pkts += 1
        cum_bytes += pkt['ip_len']
    # flush data
    out_data.append([last_frame_time_relative,
                     last_frame_time_epoch,
                     cum_frames,
                     cum_frames / period_sec,
                     cum_pkts,
                     cum_pkts / period_sec,
                     cum_bytes,
                     int(cum_bytes * 8 / period_sec)])
    return out_data


OUTPUT_HEADERS['video-frame'] = (
    'frame_time_relative', 'frame_time_epoch', 'rtp_timestamp',
    'packets', 'bytes', 'frame_video_type', 'intra_latency',
    'inter_latency', 'rtp_timestamp_latency',
)


# video-frame measures per-frame latency and inter-frame latency.
# (1) intra-frame latency: time between the first packet of each frame,
# and the last packet of the same frame *that arrives before the first
# packet of the next frame*. Let's assume that packets from frame `A`
# arrive at times `A1..Am`, and packets from frame `B` arrive at times
# `B1..Bn`. Our goal is to measure "time between the first and last
# packets of a frame", or `Am - A1` for frame A. Instead, we measure
# `Aj - A1`, where `Aj` is the last frame of A before the first frame
# from B. For example, if `A1 < A2 < ... < Aj < Bk < Aj+1 < Am`, then
# video-frame measures `Aj - A1`. This slightly-modified definition
# makes the implementation much easier, and should not make much of
# a difference, as packets are always sent in order (i.e.  `An < B1`
# at the sender).
# (2) inter-frame latency, measured as the time between the first packets
# of 2 consecutive frames.
def analyze_video_frame(parsed_rtp_list, ip_src, rtp_ssrc):
    # initialization
    out_data = []
    rtp_timestamp = None
    first_frame_time_relative = None
    first_frame_time_epoch = None
    last_frame_time_epoch = None
    cum_pkts = 0
    cum_bytes = 0
    frame_video_type = 'P'
    for pkt in parsed_rtp_list[ip_src][rtp_ssrc]:
        # first packet
        if rtp_timestamp is None or first_frame_time_epoch is None:
            rtp_timestamp = pkt['rtp_timestamp']
            first_frame_time_epoch = pkt['frame_time_epoch']
            first_frame_time_relative = pkt['frame_time_relative']
            last_frame_time_epoch = pkt['frame_time_epoch']
            cum_pkts = 0
            cum_bytes = 0
            frame_video_type = 'P'
        # check output
        if pkt['rtp_timestamp'] < rtp_timestamp:
            # old packet: ignore it
            continue
        elif pkt['rtp_timestamp'] > rtp_timestamp:
            # new frame: process data from old frame
            intra_latency = last_frame_time_epoch - first_frame_time_epoch
            inter_latency = pkt['frame_time_epoch'] - first_frame_time_epoch
            rtp_timestamp_latency = pkt['rtp_timestamp'] - rtp_timestamp
            out_data.append([first_frame_time_relative,
                             first_frame_time_epoch,
                             rtp_timestamp,
                             cum_pkts,
                             cum_bytes,
                             frame_video_type,
                             intra_latency,
                             inter_latency,
                             rtp_timestamp_latency])
            rtp_timestamp = pkt['rtp_timestamp']
            first_frame_time_epoch = pkt['frame_time_epoch']
            first_frame_time_relative = pkt['frame_time_relative']
            last_frame_time_epoch = pkt['frame_time_epoch']
            cum_bytes = 0
            cum_pkts = 0
            frame_video_type = 'P'
        else:
            # check current frame video type may be i-frame
            if (cum_pkts == 1 and
                    cum_bytes < 200 and
                    (pkt['ip_len'] * 8) > (1000 * 8)):
                # an i-frame is typically composed of a config frame
                # (containing VPS/SPS/PPS in h265, SPS/PPS in h264),
                # which is small (~150 bytes in h265, less in h264),
                # followed by a series of large packets (>1000 bytes)
                frame_video_type = 'I'
        # account for current packet
        cum_pkts += 1
        cum_bytes += pkt['ip_len']
        last_frame_time_epoch = pkt['frame_time_epoch']

    # flush data
    intra_latency = last_frame_time_epoch - first_frame_time_epoch
    inter_latency = pkt['frame_time_epoch'] - first_frame_time_epoch
    rtp_timestamp_latency = pkt['rtp_timestamp'] - rtp_timestamp
    out_data.append([first_frame_time_relative,
                     first_frame_time_epoch,
                     rtp_timestamp,
                     cum_pkts,
                     cum_bytes,
                     frame_video_type,
                     intra_latency,
                     inter_latency,
                     rtp_timestamp_latency])
    return out_data


OUTPUT_HEADERS['video-packet'] = (
    'frame_time_relative', 'frame_time_epoch', 'rtp_timestamp', 'rtp_marker',
    'bytes', 'frame_video_type', 'intra_latency',
)


# video-packet measures per-packet data, including:
# (1) intra-frame latency: time between the first packet of the frame
# corresponding to this packet, and the current packet.
def analyze_video_packet(parsed_rtp_list, ip_src, rtp_ssrc):
    # initialization
    out_data = []
    rtp_timestamp = None
    first_frame_time_epoch = None
    cum_pkts = 0
    cum_bytes = 0
    frame_video_type = 'P'
    for pkt in parsed_rtp_list[ip_src][rtp_ssrc]:
        # first packet
        if rtp_timestamp is None or first_frame_time_epoch is None:
            rtp_timestamp = pkt['rtp_timestamp']
            first_frame_time_epoch = pkt['frame_time_epoch']
            cum_pkts = 0
            cum_bytes = 0
            frame_video_type = 'P'
        # check output
        if pkt['rtp_timestamp'] > rtp_timestamp:
            # new video frame: update frame information
            rtp_timestamp = pkt['rtp_timestamp']
            first_frame_time_epoch = pkt['frame_time_epoch']
            cum_bytes = 0
            cum_pkts = 0
            frame_video_type = 'P'
        else:
            # check whether current frame video type is i-frame
            if (cum_pkts == 1 and
                    cum_bytes < 200 and
                    (pkt['ip_len'] * 8) > (1000 * 8)):
                # an i-frame is typically composed of a config frame
                # (containing VPS/SPS/PPS in h265, SPS/PPS in h264),
                # which is small (~150 bytes in h265, less in h264),
                # followed by a series of large packets (>1000 bytes)
                frame_video_type = 'I'
        # dump info for current packet
        intra_latency = pkt['frame_time_epoch'] - first_frame_time_epoch
        out_data.append([pkt['frame_time_relative'],
                         pkt['frame_time_epoch'],
                         pkt['rtp_timestamp'],
                         pkt['rtp_marker'],
                         pkt['ip_len'],
                         frame_video_type,
                         intra_latency])
        # account for current packet
        cum_pkts += 1
        cum_bytes += pkt['ip_len']

    # flush data
    intra_latency = pkt['frame_time_epoch'] - first_frame_time_epoch
    out_data.append([pkt['frame_time_relative'],
                     pkt['frame_time_epoch'],
                     pkt['rtp_timestamp'],
                     pkt['rtp_marker'],
                     pkt['ip_len'],
                     frame_video_type,
                     intra_latency])
    return out_data


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
               '-n -T fields '
               '-e frame.number '
               '-e frame.time_relative '
               '-e frame.time_epoch '
               '-e %s -e %s '
               '-e rtp.p_type '
               '-e rtcp.pt '
               '-e rtp.ssrc '
               '-e rtp.seq '
               '-e rtp.timestamp '
               '-e rtp.marker '
               '-e rtp.ext.rfc5285.data' % (
                   infile, sport, conn_filter, ip_src_field, ip_len_field))
    returncode, out, err = run(command, options)
    tshark_error_check(returncode, out, err, command)
    parsed_rtp_list, _ = parse_rtp_data(out, options)
    return parsed_rtp_list


def dump_video_statistics(video_statistics, saddr, conn_file):
    outfile = '%s.src_%s.video.csv' % (conn_file, saddr)
    with open(outfile, 'w') as f:
        f.write('# frame_time_relative, frame_time_epoch, '
                'sec_pkts, sec_bits, sec_frames, '
                'sec_max_frame_pkts, sec_max_frame_bits, sec_rtp_seq_issues, '
                'sec_frame_pkts\n')
        for (frame_time_relative, frame_time_epoch,
             sec_pkts, sec_bits, sec_frames,
             sec_max_frame_pkts, sec_max_frame_bits, sec_rtp_seq_issues,
             sec_frame_pkts) in video_statistics:
            f.write('%f.%f,%i,%i,%i,%i,%i,%i,%s\n' % (
                frame_time_relative, frame_time_epoch,
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
    # example (rtp): '2\t0.0\t1584723835.328870000\t'
    #                '2a03:2880:f231:cd:face:b00c:0:6443\t1135\t98\t\t'
    #                '0xd7346929\t27012\t1122654371\t0\tc3'
    # example (rtcp): '3\t0.00001\t1584373728.001695000\t'
    #                 '2601:647:4300:f039:e97a:e051:b8a8:a4da\t\t205'
    pkt_pattern = (
        r'(?P<frame_number>\d+)\t'
        r'(?P<frame_time_relative>[\d\.]+)\t'
        r'(?P<frame_time_epoch>[\d\.]+)\t'
        r'(?P<ip_src>' + IP_PATTERN + r')\t'
        r'(?P<ip_len>\d+)\t'
        r'(?P<rtp_p_type>\d*)\t'  # optional
        r'(?P<rtcp_pt>\d*)\t*'  # optional
        r'(?P<rtp_ssrc>0x[\da-fA-F]*)\t*'  # optional
        r'(?P<rtp_seq>\d*)\t*'  # optional
        r'(?P<rtp_timestamp>\d*)\t*'  # optional
        r'(?P<rtp_marker>\d*)\t*'  # optional
        r'(?P<rtp_ext_rfc5285_data>[\da-fA-F]*)'  # optional
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
            del entry['rtcp_pt']
            entry['rtp_ssrc'] = int(entry['rtp_ssrc'], 16)
            rtp_ssrc = '%08x' % entry['rtp_ssrc']
            entry['rtp_seq'] = int(entry['rtp_seq'])
            entry['rtp_timestamp'] = int(entry['rtp_timestamp'])
            entry['rtp_marker'] = int(entry['rtp_marker'])
            if entry['rtp_ext_rfc5285_data']:
                entry['rtp_ext_rfc5285_data'] = int(
                    entry['rtp_ext_rfc5285_data'], 16)
            if ip_src not in parsed_rtp_list:
                parsed_rtp_list[ip_src] = {}
            if rtp_ssrc not in parsed_rtp_list[ip_src]:
                parsed_rtp_list[ip_src][rtp_ssrc] = []
            parsed_rtp_list[ip_src][rtp_ssrc].append(entry)
        elif protocol == 'rtcp':
            del entry['rtp_p_type']
            entry['rtcp_pt'] = int(entry['rtcp_pt'])
            del entry['rtp_ssrc']
            del entry['rtp_seq']
            del entry['rtp_timestamp']
            del entry['rtp_marker']
            del entry['rtp_ext_rfc5285_data']
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
    parser.add_argument('-c', '--connections', action='store', type=int,
                        dest='connections',
                        default=default_values['connections'],
                        metavar='CONNECTIONS',
                        help='number of connections [default: %i]' %
                        default_values['connections'],)
    parser.add_argument('--period-sec', action='store', type=float,
                        dest='period_sec',
                        default=default_values['period_sec'],
                        metavar='PERIOD_SEC',
                        help='period in seconds [default: %f]' %
                        default_values['period_sec'],)
    parser.add_argument('-a', '--analysis', action='store', type=str,
                        dest='analysis_type',
                        default=default_values['analysis_type'],
                        choices=ANALYSIS_TYPES,
                        metavar='ANALYSIS_TYPE',
                        help='analysis type %r' % ANALYSIS_TYPES,)
    for analysis in ANALYSIS_TYPES:
        analysis_help = 'analysis type: %s (%r)' % (
            analysis,
            OUTPUT_HEADERS[analysis] if analysis != 'all' else '')
        parser.add_argument('--%s' % analysis, action='store_const',
                            dest='analysis_type', const=analysis,
                            metavar='ANALYSIS_TYPE',
                            help=analysis_help,)
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
