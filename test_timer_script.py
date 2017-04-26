#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''Unit tests for the better burp timer script.'''


import os
import sys
import timer_script
import unittest

import datetime


TEST_BACKUPS = os.path.join(os.path.dirname(__file__), '_test_data', 'backups')

def get_backup_path(backup_name = 'default'):
    return os.path.join(TEST_BACKUPS, backup_name, 'current')


class FakeTime(object):
    def __init__(self, text):
        self.fake_datetime = datetime.datetime.strptime(text, '%Y-%m-%d %H:%M:%S')
    def __enter__(self):
        self.saved_datetime = timer_script.CURRENT_DATETIME
        timer_script.CURRENT_DATETIME = self.fake_datetime
    def __exit__(self, type, value, traceback):
        timer_script.CURRENT_DATETIME = self.saved_datetime


class Test_parse_burp_duration(unittest.TestCase):

    def test_constant(self):
        assert timer_script.parse_burp_duration('3d') == datetime.timedelta(days = 3)


class Test_is_backup_continued(unittest.TestCase):

    def test_continued(self):
        assert timer_script.is_backup_continued(get_backup_path('continued'))

    def test_onepiece(self):
        assert not timer_script.is_backup_continued(get_backup_path('onepiece'))


class Test_get_backup_timestamp(unittest.TestCase):

    def test_constant(self):
        expected_timestamp = datetime.datetime.strptime('2017-04-05 12:32:07', '%Y-%m-%d %H:%M:%S')
        assert timer_script.get_backup_timestamp(get_backup_path('timestamp')) == expected_timestamp


class Test_is_backup_necessary(unittest.TestCase):

    def setUp(self):
        with open(os.path.join(get_backup_path('20h'), 'timestamp'), 'wt') as timestamp_file:
            timestamp = datetime.datetime.now().replace(microsecond = 0) - datetime.timedelta(hours = 20)
            timestamp_file.write('0000010 {}\n'.format(timestamp.isoformat(' ')))

    def test_no_conditions(self):
        assert not timer_script.is_backup_necessary(get_backup_path())

    def test_continued(self):
        assert timer_script.is_backup_necessary(get_backup_path('continued'))

    def test_new_backup(self):
        assert timer_script.is_backup_necessary(get_backup_path('empty'))

    def test_lan(self):
        backup_path = get_backup_path()

        os.environ['REMOTE_ADDR'] = '10.10.10.10'
        assert timer_script.is_backup_necessary(backup_path, '--lan')
        assert not timer_script.is_backup_necessary(backup_path, '--not-lan')

        os.environ['REMOTE_ADDR'] = '8.8.8.8'
        assert not timer_script.is_backup_necessary(backup_path, '--lan')
        assert timer_script.is_backup_necessary(backup_path, '--not-lan')

    def test_weekday(self):
        backup_path = get_backup_path()
        with FakeTime('2017-04-25 14:46:05'):
            assert timer_script.is_backup_necessary(backup_path, '--workday')
            assert not timer_script.is_backup_necessary(backup_path, '--holiday')
        with FakeTime('2017-04-22 14:46:05'):
            assert not timer_script.is_backup_necessary(backup_path, '--workday')
            assert timer_script.is_backup_necessary(backup_path, '--holiday')
        with FakeTime('2017-04-23 14:46:05'):
            assert not timer_script.is_backup_necessary(backup_path, '--workday')
            assert timer_script.is_backup_necessary(backup_path, '--holiday')

    def test_age_exceeds(self):
        backup_path = get_backup_path('20h')
        assert timer_script.is_backup_necessary(backup_path, '--age-exceeds 19h')
        assert not timer_script.is_backup_necessary(backup_path, '--age-exceeds 21h')

    def test_binary_operations(self):
        backup_path = get_backup_path('20h')
        os.environ['REMOTE_ADDR'] = '10.10.10.10'

        assert timer_script.is_backup_necessary(backup_path, '--age-exceeds 19h --lan')
        assert not timer_script.is_backup_necessary(backup_path, '--age-exceeds 19h --not-lan')
        assert not timer_script.is_backup_necessary(backup_path, '--age-exceeds 21h --lan')
        assert not timer_script.is_backup_necessary(backup_path, '--age-exceeds 21h --not-lan')

        assert timer_script.is_backup_necessary(backup_path, '--age-exceeds 19h', '--lan')
        assert timer_script.is_backup_necessary(backup_path, '--age-exceeds 19h', '--not-lan')
        assert timer_script.is_backup_necessary(backup_path, '--age-exceeds 21h', '--lan')
        assert not timer_script.is_backup_necessary(backup_path, '--age-exceeds 21h', '--not-lan')


if __name__ == '__main__':
    unittest.main()

