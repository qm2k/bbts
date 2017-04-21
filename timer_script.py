#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''The better burp timer script.'''


import os
import sys

import datetime
import gzip
import re
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
    if not os.path.exists(path):
        return None

    timestamp_filename = os.path.join(path, 'timestamp')
    with open(timestamp_filename, 'rt') as timestamp_file:
        line = timestamp_file.readline().strip('\n')
        index, timestamp_string = line.split(' ', maxsplit = 1)
        timestamp = datetime.datetime.strptime(timestamp_string, '%Y-%m-%d %H:%M:%S')
        return timestamp


def is_backup_dubious(path,
    __interrupted_backup_regex = re.compile('\d{4}-\d\d-\d\d \d\d:\d\d:\d\d: burp\[\d+\] Found interrupted backup.\n'),
):
    if not os.path.exists(path):
        return None

    log_filename = os.path.join(path, 'log.gz')
    with gzip.open(log_filename, 'rt') as log_file:
        for line in log_file:
            if __interrupted_backup_regex.fullmatch(line):
                print('Backup was being interrupted.')
                return True

    return False


def main(arguments):
    '''Main function.'''
    if len(arguments) < 7 or '--help' in arguments:
        sys.stderr.write('Usage: <client_name> <latest_path> <data_path> <reserverd1> <reserverd2> <interval>\n')
        return os.EX_USAGE
    client_name, latest_path, data_path, _, _, interval_string = arguments[1:7]
    interval = parse_burp_duration(interval_string)

    latest_timestamp = get_backup_timestamp(latest_path)
    print('Last backup: {}'.format(latest_timestamp))

    backup_is_dubious = is_backup_dubious(latest_path)
    if backup_is_dubious:
       pass
    elif latest_timestamp:
        print('Next after : {} (interval {})'.format(latest_timestamp + interval, interval_string))
    else:
        print('No prior backup of {}'.format(client_name))

    current_timestamp = datetime.datetime.now()
    if backup_is_dubious or not latest_timestamp or latest_timestamp + interval < current_timestamp:
        print('Do a backup of {} now.'.format(client_name))
        return 0
    else:
        print('Not yet time for a backup of {}.'.format(client_name))
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))


