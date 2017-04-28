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
        assert timer_script.parse_time_of_day_interval('1T2:3..4T5:6') == expected_result

    def test_negative(self):
        expected_result = timer_script.Interval(
            start = datetime.timedelta(days = -1, hours = 2, minutes = 3),
            end = datetime.timedelta(days = -4, hours = 5, minutes = 6))
        assert timer_script.parse_time_of_day_interval('-1T2:3..-4T5:6') == expected_result


class Test_is_backup_continued(unittest.TestCase):

    def test_continued(self):
        assert timer_script.is_backup_continued(get_backup_path('continued'))

    def test_onepiece(self):
        assert not timer_script.is_backup_continued(get_backup_path('onepiece'))


class Test_get_backup_timestamp(unittest.TestCase):

    def test_constant(self):
        expected_result = datetime.datetime.strptime('2017-04-05 12:32:07', '%Y-%m-%d %H:%M:%S')
        assert timer_script.get_backup_timestamp(get_backup_path('timestamp')) == expected_result

    def test_dynamic(self):
        backup_path = get_backup_path('dynamic_timestamp')
        timestamp = datetime.datetime.now()
        timer_script.write_timestamp(os.path.join(backup_path, 'timestamp'), timestamp)
        expected_result = timestamp.replace(microsecond = 0)
        assert timer_script.get_backup_timestamp(get_backup_path('dynamic_timestamp')) == expected_result


class Test_check_conditions(unittest.TestCase):

    def setUp(self):
        filename = os.path.join(get_backup_path('20h'), 'timestamp')
        timestamp = datetime.datetime.now() - datetime.timedelta(hours = 20)
        timer_script.write_timestamp(filename, timestamp)

        filename = os.path.join(get_backup_path('yesterday9'), 'timestamp')
        timestamp = datetime.datetime.combine(
            datetime.datetime.now().date() - datetime.timedelta(days = 1),
            datetime.time(hour = 9))
        timer_script.write_timestamp(filename, timestamp)

    def test_no_conditions(self):
        assert not timer_script.check_conditions(get_backup_path())
        assert not timer_script.check_conditions(get_backup_path('empty'))

    def test_no_arguments(self):
        with self.assertRaises(ValueError):
            timer_script.check_conditions(get_backup_path(), '')
        with self.assertRaises(ValueError):
            timer_script.check_conditions(get_backup_path('empty'), '')
        with self.assertRaises(ValueError):
            timer_script.check_conditions(get_backup_path(), '# this is a comment --lan')
        with self.assertRaises(ValueError):
            timer_script.check_conditions(get_backup_path('empty'), '# this is a comment --lan')

    def test_comment(self):
        assert timer_script.check_conditions(get_backup_path('continued'), '--continued # this is another comment --lan')
        assert not timer_script.check_conditions(get_backup_path('onepiece'), '--continued # this is another comment --lan')

    def test_continued(self):
        assert timer_script.check_conditions(get_backup_path('continued'), '--continued')
        assert not timer_script.check_conditions(get_backup_path('onepiece'))

    def test_new_backup(self):
        backup_path = get_backup_path()
        assert not timer_script.check_conditions(backup_path, '--new')
        assert timer_script.check_conditions(backup_path, '--not-new')

        backup_path = get_backup_path('empty')
        assert timer_script.check_conditions(backup_path, '--new')
        assert not timer_script.check_conditions(backup_path, '--not-new')
        assert timer_script.check_conditions(backup_path, '--age-exceeds 20h')
        assert not timer_script.check_conditions(backup_path, '--continued')
        with RemoteAddress('8.8.8.8'):
            assert timer_script.check_conditions(backup_path, '--not-lan')
            assert not timer_script.check_conditions(backup_path, '--lan')

    def test_init_exceeds(self):
        assert not timer_script.check_conditions(get_backup_path('20h'), '--init-exceeds 1h')

        backup_path = get_backup_path('dynamic_presence')
        if os.path.exists(backup_path):
            os.rmdir(backup_path)
        created_timestamp_filename = os.path.join(os.path.split(backup_path)[0], 'created_timestamp')
        if os.path.exists(created_timestamp_filename):
            os.remove(created_timestamp_filename)

        assert not os.path.exists(created_timestamp_filename)
        assert not timer_script.check_conditions(backup_path, '--init-exceeds 1h')

        assert os.path.exists(created_timestamp_filename)
        assert not timer_script.check_conditions(backup_path, '--init-exceeds 1h')

        timestamp = datetime.datetime.now() - datetime.timedelta(hours = 20)
        timer_script.write_timestamp(created_timestamp_filename, timestamp)
        assert timer_script.check_conditions(backup_path, '--init-exceeds 19h')
        assert not timer_script.check_conditions(backup_path, '--init-exceeds 21h')

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

    def test_prior_before(self):
        backup_path = get_backup_path('yesterday9')
        assert timer_script.check_conditions(backup_path, '--prior-before 9')
        assert timer_script.check_conditions(backup_path, '--prior-before 8')
        assert timer_script.check_conditions(backup_path, '--prior-before=-1T10')
        assert not timer_script.check_conditions(backup_path, '--prior-before=-1T9')
        assert not timer_script.check_conditions(backup_path, '--prior-before=-1T8')

    def test_prior_before__and__after(self):
        backup_path = get_backup_path('yesterday9')
        assert timer_script.check_conditions(backup_path, '--prior-before=-1T10 --after 0')
        assert not timer_script.check_conditions(backup_path, '--prior-before=-1T9 --after 0')
        assert timer_script.check_conditions(backup_path, '--prior-before 10 --after 24')
        assert not timer_script.check_conditions(backup_path, '--prior-before 9 --after 24')
        assert timer_script.check_conditions(backup_path, '--after 24 --prior-before 10')
        assert not timer_script.check_conditions(backup_path, '--after 24 --prior-before 9')

    def test_prior_before__and__time(self):
        backup_path = get_backup_path('yesterday9')
        assert timer_script.check_conditions(backup_path, '--prior-before=-1T10 --time 0..24')
        assert not timer_script.check_conditions(backup_path, '--prior-before=-1T9 --time 0..24')
        assert timer_script.check_conditions(backup_path, '--prior-before 10 --time 1T0..2T0')
        assert not timer_script.check_conditions(backup_path, '--prior-before 9 --time 1T0..2T0')
        assert timer_script.check_conditions(backup_path, '--time 1T0..2T0 --prior-before 10')
        assert not timer_script.check_conditions(backup_path, '--time 1T0..2T0 --prior-before 9')

    def test_after(self):
        backup_path = get_backup_path()
        with FakeTime('2017-04-24 14:46:05'):
            assert timer_script.check_conditions(backup_path, '--after 14:46')
            assert timer_script.check_conditions(backup_path, '--after 14:46:05')
            assert timer_script.check_conditions(backup_path, '--after 14:45')
            assert timer_script.check_conditions(backup_path, '--after 14:45:04')
            assert timer_script.check_conditions(backup_path, '--after 14:47')

            assert timer_script.check_conditions(backup_path, '--after 38')
            assert timer_script.check_conditions(backup_path, '--after 37')
            assert timer_script.check_conditions(backup_path, '--after 39')

            assert timer_script.check_conditions(backup_path, '--after=-10')
            assert timer_script.check_conditions(backup_path, '--after=-9')
            assert timer_script.check_conditions(backup_path, '--after=-11')

    def test_after__and__time(self):
        backup_path = get_backup_path()
        with FakeTime('2017-04-24 14:46:05'):
            with self.assertRaises(ValueError):
                timer_script.check_conditions(backup_path, '--after 14:46 --time 14:45..14:46')
            with self.assertRaises(ValueError):
                timer_script.check_conditions(backup_path, '--after 14:46 --time 14:46..14:47')
            with self.assertRaises(ValueError):
                timer_script.check_conditions(backup_path, '--after 14:46 --time 14:47..14:48')

    def test_weekday__and__after(self):
        backup_path = get_backup_path()
        with FakeTime('2017-04-24 14:46:05'):
            assert timer_script.check_conditions(backup_path, '--after 14 --workday')
            assert not timer_script.check_conditions(backup_path, '--after 14 --holiday')
            assert not timer_script.check_conditions(backup_path, '--after 38 --workday')
            assert timer_script.check_conditions(backup_path, '--after 38 --holiday')

    def test_time(self):
        backup_path = get_backup_path()
        with FakeTime('2017-04-24 14:46:05'):
            assert timer_script.check_conditions(backup_path, '--time 14:46..14:47')
            assert timer_script.check_conditions(backup_path, '--time 14:46:05..14:46:06')
            assert not timer_script.check_conditions(backup_path, '--time 14:45..14:46')
            assert not timer_script.check_conditions(backup_path, '--time 14:45:04..14:46:05')
            assert not timer_script.check_conditions(backup_path, '--time 14:47..14:48')

            assert timer_script.check_conditions(backup_path, '--time 38..39')
            assert not timer_script.check_conditions(backup_path, '--time 37..38')
            assert not timer_script.check_conditions(backup_path, '--time 39..40')

            assert timer_script.check_conditions(backup_path, '--time=-10..-9')
            assert not timer_script.check_conditions(backup_path, '--time=-9..-8')
            assert not timer_script.check_conditions(backup_path, '--time=-11..-10')

    def test_weekday__and__time(self):
        backup_path = get_backup_path()
        with FakeTime('2017-04-24 14:46:05'):
            assert timer_script.check_conditions(backup_path, '--time 14..15,38..39 --workday')
            assert not timer_script.check_conditions(backup_path, '--time 14..15,38..39 --holiday')
            assert not timer_script.check_conditions(backup_path, '--time 38..39,14..15 --workday')
            assert timer_script.check_conditions(backup_path, '--time 38..39,14..15 --holiday')

            assert not timer_script.check_conditions(backup_path, '--time 13..14,38..39 --workday')
            assert timer_script.check_conditions(backup_path, '--time 13..14,38..39 --holiday')
            assert timer_script.check_conditions(backup_path, '--time 37..38,14..15 --workday')
            assert not timer_script.check_conditions(backup_path, '--time 37..38,14..15 --holiday')

            assert timer_script.check_conditions(backup_path, '--time 14..15 --workday')
            assert not timer_script.check_conditions(backup_path, '--time 14..15 --holiday')
            assert not timer_script.check_conditions(backup_path, '--time 38..39 --workday')
            assert timer_script.check_conditions(backup_path, '--time 38..39 --holiday')

    def test_time__combinations(self):
        backup_path = get_backup_path()
        with FakeTime('2017-04-24 14:46:05'):
            assert timer_script.check_conditions(backup_path, '--time 13..14,14..15,16..17')
            assert timer_script.check_conditions(backup_path, '--time 13..14', '--time 16..17,14..15')
            assert timer_script.check_conditions(backup_path, '--time 13..14,14..15', '--time 16..17')
            assert timer_script.check_conditions(backup_path, '--time 13..14', '--time 14..15', '--time 16..17')

            assert not timer_script.check_conditions(backup_path, '--time 13..14,15..16,16..17')
            assert not timer_script.check_conditions(backup_path, '--time 13..14', '--time 16..17,15..16')
            assert not timer_script.check_conditions(backup_path, '--time 13..14,15..16', '--time 16..17')
            assert not timer_script.check_conditions(backup_path, '--time 13..14', '--time 15..16', '--time 16..17')

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

    def test_stop(self):
        backup_path = get_backup_path('20h')
        with RemoteAddress('10.10.10.10'):
            assert not timer_script.check_conditions(backup_path, '--age-exceeds 19h --lan --stop')
            assert not timer_script.check_conditions(backup_path, '--age-exceeds 19h --not-lan --stop')
            assert not timer_script.check_conditions(backup_path, '--age-exceeds 21h --lan --stop')
            assert not timer_script.check_conditions(backup_path, '--age-exceeds 21h --not-lan --stop')

            assert not timer_script.check_conditions(backup_path, '--age-exceeds 19h --stop', '--lan')
            assert not timer_script.check_conditions(backup_path, '--age-exceeds 19h --stop', '--not-lan')
            assert timer_script.check_conditions(backup_path, '--age-exceeds 21h --stop', '--lan')
            assert not timer_script.check_conditions(backup_path, '--age-exceeds 21h --stop', '--not-lan')

            assert timer_script.check_conditions(backup_path, '--age-exceeds 19h', '--lan --stop')
            assert timer_script.check_conditions(backup_path, '--age-exceeds 19h', '--not-lan --stop')
            assert not timer_script.check_conditions(backup_path, '--age-exceeds 21h', '--lan --stop')
            assert not timer_script.check_conditions(backup_path, '--age-exceeds 21h', '--not-lan --stop')


if __name__ == '__main__':
    unittest.main()

