#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''The better burp timer script.'''


import os
import sys

import argparse
import datetime
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


def get_backup_timestamp(path):
    timestamp_filename = os.path.join(path, 'timestamp')
    with open(timestamp_filename, 'rt') as timestamp_file:
        line = timestamp_file.readline().strip('\n')
        index, timestamp_string = line.split(' ', maxsplit = 1)
        timestamp = datetime.datetime.strptime(timestamp_string, '%Y-%m-%d %H:%M:%S')
        return timestamp


def get_argument_parser():
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument('interval', type = parse_burp_duration)
    argument_parser.add_argument('--private-ip', action = 'store_true')
    argument_parser.add_argument('--workday', action = 'store_true')
    argument_parser.add_argument('--holiday', action = 'store_true')
    argument_parser.add_argument('--hours-range', action = 'append')
    return argument_parser


def match_hours_ranges(hours_ranges):
    for hours_range in hours_ranges:
        first_hour, last_hour = hours_range.split('..')
        first_hour = int(first_hour) if first_hour else 0
        last_hour = int(last_hour) if last_hour else 24
        if first_hour <= CURRENT_DATETIME.hour <= last_hour:
            return True
    return False


def get_interval(argument_strings, __argument_parser = get_argument_parser()):
    for argument_string in argument_strings:
        arguments = __argument_parser.parse_args(shlex.split(argument_string))
        if arguments.private_ip and not ipaddress.ip_address(os.environ['REMOTE_ADDR']).is_private:
            continue
        if arguments.workday and not CURRENT_DATETIME.weekday() < 5:
            continue
        if arguments.holiday and not CURRENT_DATETIME.weekday() >= 5:
            continue
        if arguments.hours_range and not match_hours_ranges(arguments.hours_range):
            continue
        return arguments.interval
    raise ValueError('Interval cannot be determined', argument_strings)


def is_backup_dubious(path,
    __interrupted_backup_regex = re.compile('\d{4}-\d\d-\d\d \d\d:\d\d:\d\d: burp\[\d+\] Found interrupted backup.\n'),
):
    log_filename = os.path.join(path, 'log.gz')
    with gzip.open(log_filename, 'rt') as log_file:
        for line in log_file:
            if __interrupted_backup_regex.fullmatch(line):
                print('Backup was being interrupted.')
                return True

    return False


def is_backup_necessary(latest_path, interval):
    if not os.path.exists(latest_path):
        print('No prior backup.')
        return True

    if is_backup_dubious(latest_path):
        print('Prior backup is dubious.')
        return True

    latest_timestamp = get_backup_timestamp(latest_path)
    print('Last backup: {}, interval: {}'.format(latest_timestamp, interval))

    next_timestamp = latest_timestamp + interval
    if next_timestamp < CURRENT_DATETIME:
        return True

    print('Next after : {}'.format(next_timestamp))
    return False


def main(arguments):
    '''Main function.'''
    if len(arguments) < 7 or '--help' in arguments:
        sys.stderr.write('Usage: <client_name> <latest_path> <data_path> <reserverd1> <reserverd2> <argument_strings>\n')
        return os.EX_USAGE
    client_name, latest_path, data_path = arguments[1:4]
    argument_strings = arguments[6:]
    interval = get_interval(argument_strings)

    backup_is_necessary = is_backup_necessary(latest_path, interval)
    if backup_is_necessary:
        print('Do backup now.'.format(client_name))
        return os.EX_OK

    return not os.EX_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv))


