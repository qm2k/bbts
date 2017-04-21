#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''The better burp timer script.'''


import os
import sys

import argparse
import datetime
import gzip
import re
import shlex
import subprocess


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
    return argument_parser


def get_interval(argument_strings, __argument_parser = get_argument_parser()):
    for argument_string in argument_strings:
        arguments = __argument_parser.parse_args(shlex.split(argument_string))
        return arguments.interval


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
    current_timestamp = datetime.datetime.now()
    if next_timestamp < current_timestamp:
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


