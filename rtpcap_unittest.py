#!/usr/bin/env python3
# Copyright (c) Facebook, Inc. and its affiliates.

"""rtpcap_unittest.py: simple unittest.


"""

import importlib
import unittest

rtpcap = importlib.import_module('rtpcap')


getPacketLossAndOutOfOrderTestCases = [
    {
        'name': 'basic',
        'rtp_seq_prev': 1,
        'rtp_seq_list': [2, 3, 4],
        'ploss': 0,
        'porder': 0,
        'pdups': 0,
        'rtp_seq_max': 4,
    },
    {
        'name': 'empty rtp_seq_prev',
        'rtp_seq_prev': None,
        'rtp_seq_list': [2, 3, 4],
        'ploss': 0,
        'porder': 0,
        'pdups': 0,
        'rtp_seq_max': 4,
    },
    {
        'name': 'empty rtp_seq_list',
        'rtp_seq_prev': 1,
        'rtp_seq_list': [],
        'ploss': 0,
        'porder': 0,
        'pdups': 0,
        'rtp_seq_max': 1,
    },
    {
        'name': 'ploss 1',
        'rtp_seq_prev': 1,
        'rtp_seq_list': [2, 4],
        'ploss': 1,
        'porder': 0,
        'pdups': 0,
        'rtp_seq_max': 4,
    },
    {
        'name': 'ploss 2',
        'rtp_seq_prev': 0,
        'rtp_seq_list': [2, 3],
        'ploss': 1,
        'porder': 0,
        'pdups': 0,
        'rtp_seq_max': 3,
    },
    {
        'name': 'porder 1',
        'rtp_seq_prev': 1,
        'rtp_seq_list': [2, 4, 3],
        'ploss': 0,
        'porder': 1,
        'pdups': 0,
        'rtp_seq_max': 4,
    },
    {
        'name': 'porder 2',
        'rtp_seq_prev': 2,
        'rtp_seq_list': [1, 3, 4],
        'ploss': 0,
        'porder': 1,
        'pdups': 0,
        'rtp_seq_max': 4,
    },
    {
        'name': 'pdups 1',
        'rtp_seq_prev': 1,
        'rtp_seq_list': [2, 3, 3, 4],
        'ploss': 0,
        'porder': 0,
        'pdups': 1,
        'rtp_seq_max': 4,
    },
    {
        'name': 'pdups 2',
        'rtp_seq_prev': 1,
        'rtp_seq_list': [1, 2, 3, 4],
        'ploss': 0,
        'porder': 0,
        'pdups': 1,
        'rtp_seq_max': 4,
    },
    {
        'name': 'porder and ploss',
        'rtp_seq_prev': 1,
        'rtp_seq_list': [2, 4, 3, 6],
        'ploss': 1,
        'porder': 1,
        'pdups': 0,
        'rtp_seq_max': 6,
    },
    {
        'name': 'porder and pdups',
        'rtp_seq_prev': 1,
        'rtp_seq_list': [2, 4, 3, 3],
        'ploss': 0,
        'porder': 1,
        'pdups': 1,
        'rtp_seq_max': 4,
    },
    {
        'name': 'ploss and pdups',
        'rtp_seq_prev': 1,
        'rtp_seq_list': [2, 2, 4, 5],
        'ploss': 1,
        'porder': 0,
        'pdups': 1,
        'rtp_seq_max': 5,
    },
    {
        'name': 'porder, ploss, pdups',
        'rtp_seq_prev': 1,
        'rtp_seq_list': [2, 2, 5, 4],
        'ploss': 1,
        'porder': 1,
        'pdups': 1,
        'rtp_seq_max': 5,
    },
]


analyzeVideoFrameTestCases = [
    {
        'name': 'basic',
        'parsed_rtp_list': [
            {
                'frame_number': 164,
                'frame_time_relative': 8.258306,
                'frame_time_epoch': 1596055127.588039,
                'ip_src': '192.0.2.1',
                'ip_len': 115,
                'rtp_p_type': 127,
                'rtp_ssrc': 564448287,
                'rtp_seq': 9017,
                'rtp_timestamp': 541511905,
                'rtp_marker': 0,
                'rtp_ext_rfc5285_data': 1,
            },
            {
                'frame_number': 166,
                'frame_time_relative': 8.263017,
                'frame_time_epoch': 1596055127.59275,
                'ip_src': '192.0.2.1',
                'ip_len': 1137,
                'rtp_p_type': 127,
                'rtp_ssrc': 564448287,
                'rtp_seq': 9018,
                'rtp_timestamp': 541511905,
                'rtp_marker': 0,
                'rtp_ext_rfc5285_data': 2,
            },
            {
                'frame_number': 168,
                'frame_time_relative': 8.271022,
                'frame_time_epoch': 1596055127.600755,
                'ip_src': '192.0.2.1',
                'ip_len': 1137,
                'rtp_p_type': 127,
                'rtp_ssrc': 564448287,
                'rtp_seq': 9019,
                'rtp_timestamp': 541511905,
                'rtp_marker': 0,
                'rtp_ext_rfc5285_data': 3,
            },
            {
                'frame_number': 169,
                'frame_time_relative': 8.279998,
                'frame_time_epoch': 1596055127.609731,
                'ip_src': '192.0.2.1',
                'ip_len': 1137,
                'rtp_p_type': 127,
                'rtp_ssrc': 564448287,
                'rtp_seq': 9020,
                'rtp_timestamp': 541511905,
                'rtp_marker': 0,
                'rtp_ext_rfc5285_data': 4,
            },
            {
                'frame_number': 174,
                'frame_time_relative': 8.292757,
                'frame_time_epoch': 1596055127.62249,
                'ip_src': '192.0.2.1',
                'ip_len': 1137,
                'rtp_p_type': 127,
                'rtp_ssrc': 564448287,
                'rtp_seq': 9021,
                'rtp_timestamp': 541511905,
                'rtp_marker': 0,
                'rtp_ext_rfc5285_data': 5,
            },
        ],
        'out_data': [
            # 'frame_time_relative', 'frame_time_epoch', 'rtp_timestamp',
            # 'packets', 'bytes', 'frame_video_type', 'intra_latency',
            # 'inter_latency', 'rtp_timestamp_latency',
            [8.258306, 1596055127.588039, 541511905, 5, 4663, 'I',
             0.03445100784301758, 0.03445100784301758, 0],
        ],
    },
]


class MyTest(unittest.TestCase):

    def testGetPacketLossAndOutOfOrder(self):
        """Simplest get_packets_loss_and_out_of_order test."""
        for test_case in getPacketLossAndOutOfOrderTestCases:
            ploss, porder, pdups, rtp_seq_max = (
                rtpcap.get_packets_loss_and_out_of_order(
                    test_case['rtp_seq_prev'],
                    test_case['rtp_seq_list']))
            msg = 'unittest failed: %s' % test_case['name']
            self.assertEqual(test_case['ploss'], ploss, msg=msg)
            self.assertEqual(test_case['porder'], porder, msg=msg)
            self.assertEqual(test_case['pdups'], pdups, msg=msg)
            self.assertEqual(test_case['rtp_seq_max'], rtp_seq_max, msg=msg)

    def testAnalyzeVideoFrame(self):
        """Simplest analize_video_frame tests."""
        for test_case in analyzeVideoFrameTestCases:
            ip_src = 'ip_src'
            rtp_ssrc = 'rtp_ssrc'
            parsed_rtp_list = {
                'ip_src': {
                    'rtp_ssrc': test_case['parsed_rtp_list']
                }
            }
            out_data = rtpcap.analyze_video_frame(
                parsed_rtp_list, ip_src, rtp_ssrc)
            msg = 'unittest failed: %s' % test_case['name']
            self.assertEqual(test_case['out_data'], out_data, msg=msg)


if __name__ == '__main__':
    unittest.main()
