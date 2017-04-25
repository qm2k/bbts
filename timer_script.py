#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''The better burp timer script.'''


import os
import sys

import argparse
import datetime
import collections
import gzip
import ipaddress
import re
import shlex
import subprocess


CURRENT_DATETIME = datetime.datetime.now()


def parse_burp_duration(duration_string,
    __regex = re.compile('(?P<number>\d+)(?P<unit>[smhdwn])'),
    __unit_to_seconds = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 7*86400, 'n': 30*86400}
):
    match = __regex.fullmatch(duration_string)
    if not match:
        raise ValueError(duration_string)
    return datetime.timedelta(seconds = int(match.group('number')) * __unit_to_seconds[match.group('unit')])


def is_backup_continued(backup_path,
    __interrupted_backup_regex = re.compile('\d{4}-\d\d-\d\d \d\d:\d\d:\d\d: burp\[\d+\] Found interrupted backup.\n'),
):
    log_filename = os.path.join(backup_path, 'log.gz')
    with gzip.open(log_filename, 'rt') as log_file:
        for line in log_file:
            if __interrupted_backup_regex.fullmatch(line):
                return True

    return False


def get_backup_timestamp(backup_path):
    timestamp_filename = os.path.join(backup_path, 'timestamp')
    with open(timestamp_filename, 'rt') as timestamp_file:
        line = timestamp_file.readline().strip('\n')
        index, timestamp_string = line.split(' ', maxsplit = 1)
        timestamp = datetime.datetime.strptime(timestamp_string, '%Y-%m-%d %H:%M:%S')
        return timestamp


Condition = collections.namedtuple('Condition', ('name', 'argument_action', 'call'))


def match_argument_strings(latest_path, *argument_strings):

    def match_hours_ranges(hours_ranges):
        for hours_range in hours_ranges:
            first_hour, last_hour = hours_range.split('..')
            first_hour = int(first_hour) if first_hour else 0
            last_hour = int(last_hour) if last_hour else 24
            if first_hour <= CURRENT_DATETIME.hour <= last_hour:
                return True
        return False

    def remote_address():
        return ipaddress.ip_address(os.environ['REMOTE_ADDR'])

    def weekday():
        return CURRENT_DATETIME.weekday()

    def age_exceeds(maximum_age_string):
        return CURRENT_DATETIME > get_backup_timestamp(latest_path) + parse_burp_duration(maximum_age_string)

    conditions = (
        Condition(name = 'lan', argument_action = 'store_true', call = lambda: remote_address().is_private),
        Condition(name = 'not_lan', argument_action = 'store_true', call = lambda: not remote_address().is_private),
        Condition(name = 'workday', argument_action = 'store_true', call = lambda: weekday() < 5),
        Condition(name = 'holiday', argument_action = 'store_true', call = lambda: weekday() >= 5),
        Condition(name = 'age_exceeds', argument_action = 'store', call = age_exceeds),
    )

    parser = argparse.ArgumentParser()
    for condition in conditions:
        parser.add_argument('--' + condition.name.replace('_', '-'), action = condition.argument_action)

    def match_conditions(arguments):
        for condition in conditions:
            argument_value = arguments.get(condition.name, None)
            if argument_value in (None, False):
                continue
            condition_arguments = (argument_value,) if argument_value != True else ()
            if not condition.call(*condition_arguments):
                return False
        return True

    for argument_string in argument_strings:
        if match_conditions(vars(parser.parse_args(shlex.split(argument_string)))):
            return True

    return False


def is_backup_necessary(latest_path, *argument_strings):
    if not os.path.exists(latest_path):
        return True

    if is_backup_continued(latest_path):
        return True

    return match_argument_strings(latest_path, *argument_strings)


def main(arguments):
    '''Main function.'''
    if len(arguments) < 7 or '--help' in arguments:
        sys.stderr.write('Usage: <client_name> <latest_path> <data_path> <reserverd1> <reserverd2> <argument_strings...>\n')
        return os.EX_USAGE
    client_name, latest_path, data_path = arguments[1:4]
    argument_strings = arguments[6:]

    return os.EX_OK if is_backup_necessary(latest_path, *argument_strings) else not os_EX_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv))


