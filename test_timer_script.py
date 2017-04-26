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


class RemoteAddress(object):
    def __init__(self, remote_address):
        self.remote_address = remote_address
    def __enter__(self):
        os.environ['REMOTE_ADDR'] = self.remote_address
    def __exit__(self, type, value, traceback):
        del os.environ['REMOTE_ADDR']


class Test_parse_burp_duration(unittest.TestCase):

    def test_constant(self):
        assert timer_script.parse_burp_duration('3d') == datetime.timedelta(days = 3)


class Test_parse_time_of_day(unittest.TestCase):

    def test_hour_only(self):
        expected_result = datetime.timedelta(hours = 1)
        assert timer_script.parse_time_of_day('1') == expected_result
        assert timer_script.parse_time_of_day('T1') == expected_result

    def test_time_only(self):
        expected_result = datetime.timedelta(hours = 1, minutes = 2, seconds = 3)
        assert timer_script.parse_time_of_day('01:02:03') == expected_result
        assert timer_script.parse_time_of_day('T01:02:03') == expected_result

    def test_time_and_day(self):
        expected_result = datetime.timedelta(days = 1, hours = 2, minutes = 3, seconds = 4)
        assert timer_script.parse_time_of_day('1 02:03:04') == expected_result
        assert timer_script.parse_time_of_day('1T02:03:04') == expected_result

    def test_negative(self):
        expected_result = datetime.timedelta(days = -1, hours = -2, minutes = -3, seconds = -4)
        assert timer_script.parse_time_of_day('-1 -02:-03:-04') == expected_result
        assert timer_script.parse_time_of_day('-1T-02:-03:-04') == expected_result

    def test_partial(self):
        expected_result = datetime.timedelta(days = 1, hours = 2)
        assert timer_script.parse_time_of_day('1T2') == expected_result
        assert timer_script.parse_time_of_day('1 2') == expected_result
        assert timer_script.parse_time_of_day('1T2:0') == expected_result
        assert timer_script.parse_time_of_day('1 2:0') == expected_result

    def test_hour_only(self):
        expected_result = datetime.timedelta(hours = 1)
        assert timer_script.parse_time_of_day('1') == expected_result
        assert timer_script.parse_time_of_day('T1') == expected_result


class Test_parse_time_of_day_interval(unittest.TestCase):

    def test_constant(self):
        expected_result = timer_script.Interval(
            start = datetime.timedelta(days = 1, hours = 2, minutes = 3),
            end = datetime.timedelta(days = 4, hours = 5, minutes = 6))
        assert timer_script.parse_time_of_day_interval('1T2:3/4T5:6') == expected_result
        assert timer_script.parse_time_of_day_interval('1T2:3--4T5:6') == expected_result

    def test_negative(self):
        expected_result = timer_script.Interval(
            start = datetime.timedelta(days = -1, hours = 2, minutes = 3),
            end = datetime.timedelta(days = -4, hours = 5, minutes = 6))
        assert timer_script.parse_time_of_day_interval('-1T2:3/-4T5:6') == expected_result
        assert timer_script.parse_time_of_day_interval('-1T2:3---4T5:6') == expected_result


class Test_is_backup_continued(unittest.TestCase):

    def test_continued(self):
        assert timer_script.is_backup_continued(get_backup_path('continued'))

    def test_onepiece(self):
        assert not timer_script.is_backup_continued(get_backup_path('onepiece'))


class Test_get_backup_timestamp(unittest.TestCase):

    def test_constant(self):
        expected_result = datetime.datetime.strptime('2017-04-05 12:32:07', '%Y-%m-%d %H:%M:%S')
        assert timer_script.get_backup_timestamp(get_backup_path('timestamp')) == expected_result


class Test_check_conditions(unittest.TestCase):

    def setUp(self):
        with open(os.path.join(get_backup_path('20h'), 'timestamp'), 'wt') as timestamp_file:
            timestamp = datetime.datetime.now().replace(microsecond = 0) - datetime.timedelta(hours = 20)
            timestamp_file.write('0000010 {}\n'.format(timestamp.isoformat(' ')))

    def test_no_conditions(self):
        assert not timer_script.check_conditions(get_backup_path())

    def test_continued(self):
        assert timer_script.check_conditions(get_backup_path('continued'), '--continued')
        assert not timer_script.check_conditions(get_backup_path('onepiece'))

    def test_new_backup(self):
        backup_path = get_backup_path('empty')
        assert not timer_script.check_conditions(backup_path)
        assert timer_script.check_conditions(backup_path, '--age-exceeds 20h')
        assert not timer_script.check_conditions(backup_path, '--continued')
        with RemoteAddress('8.8.8.8'):
            assert timer_script.check_conditions(backup_path, '--not-lan')
            assert not timer_script.check_conditions(backup_path, '--lan')

    def test_lan(self):
        backup_path = get_backup_path()
        with RemoteAddress('10.10.10.10'):
            assert timer_script.check_conditions(backup_path, '--lan')
            assert not timer_script.check_conditions(backup_path, '--not-lan')
        with RemoteAddress('8.8.8.8'):
            assert not timer_script.check_conditions(backup_path, '--lan')
            assert timer_script.check_conditions(backup_path, '--not-lan')

    def test_subnet(self):
        backup_path = get_backup_path()
        with RemoteAddress('10.1.1.1'):
            assert timer_script.check_conditions(backup_path, '--subnet 10.1.1.0/24')
            assert timer_script.check_conditions(backup_path, '--subnet 10.0.0.0/24,10.1.1.0/24')
            assert not timer_script.check_conditions(backup_path, '--subnet 10.0.0.0/24,10.2.2.0/24')
            assert timer_script.check_conditions(backup_path, '--not-subnet 10.0.0.0/24')
            assert timer_script.check_conditions(backup_path, '--not-subnet 10.0.0.0/24,10.2.2.0/24')
            assert not timer_script.check_conditions(backup_path, '--not-subnet 10.0.0.0/24,10.1.1.0/24')

    def test_weekday(self):
        backup_path = get_backup_path()
        with FakeTime('2017-04-25 14:46:05'):
            assert timer_script.check_conditions(backup_path, '--workday')
            assert not timer_script.check_conditions(backup_path, '--holiday')
        with FakeTime('2017-04-22 14:46:05'):
            assert not timer_script.check_conditions(backup_path, '--workday')
            assert timer_script.check_conditions(backup_path, '--holiday')
        with FakeTime('2017-04-23 14:46:05'):
            assert not timer_script.check_conditions(backup_path, '--workday')
            assert timer_script.check_conditions(backup_path, '--holiday')

    def test_age_exceeds(self):
        backup_path = get_backup_path('20h')
        assert timer_script.check_conditions(backup_path, '--age-exceeds 19h')
        assert not timer_script.check_conditions(backup_path, '--age-exceeds 21h')

    def test_current_time(self):
        backup_path = get_backup_path()
        with FakeTime('2017-04-25 14:46:05'):
            assert timer_script.check_conditions(backup_path, '--time 14:46--14:47')
            assert timer_script.check_conditions(backup_path, '--time 14:46:05--14:46:06')
            assert not timer_script.check_conditions(backup_path, '--time 14:45--14:46')
            assert not timer_script.check_conditions(backup_path, '--time 14:45:04--14:46:05')
            assert not timer_script.check_conditions(backup_path, '--time 14:47--14:48')

    def test_current_time__multiple(self):
        backup_path = get_backup_path()
        with FakeTime('2017-04-25 14:46:05'):
            assert timer_script.check_conditions(backup_path, '--time 13--14,14--15,16--17')
            assert timer_script.check_conditions(backup_path, '--time 13--14', '--time 16--17,14--15')
            assert timer_script.check_conditions(backup_path, '--time 13--14,14--15', '--time 16--17')
            assert timer_script.check_conditions(backup_path, '--time 13--14', '--time 14--15', '--time 16--17')
            assert not timer_script.check_conditions(backup_path, '--time 13--14,15--16,16--17')
            assert not timer_script.check_conditions(backup_path, '--time 13--14', '--time 16--17,15--16')
            assert not timer_script.check_conditions(backup_path, '--time 13--14,15--16', '--time 16--17')
            assert not timer_script.check_conditions(backup_path, '--time 13--14', '--time 15--16', '--time 16--17')

    def test_binary_operations(self):
        backup_path = get_backup_path('20h')
        with RemoteAddress('10.10.10.10'):
            assert timer_script.check_conditions(backup_path, '--age-exceeds 19h --lan')
            assert not timer_script.check_conditions(backup_path, '--age-exceeds 19h --not-lan')
            assert not timer_script.check_conditions(backup_path, '--age-exceeds 21h --lan')
            assert not timer_script.check_conditions(backup_path, '--age-exceeds 21h --not-lan')

            assert timer_script.check_conditions(backup_path, '--age-exceeds 19h', '--lan')
            assert timer_script.check_conditions(backup_path, '--age-exceeds 19h', '--not-lan')
            assert timer_script.check_conditions(backup_path, '--age-exceeds 21h', '--lan')
            assert not timer_script.check_conditions(backup_path, '--age-exceeds 21h', '--not-lan')


if __name__ == '__main__':
    unittest.main()

