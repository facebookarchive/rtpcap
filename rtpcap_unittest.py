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


if __name__ == '__main__':
    unittest.main()
