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

CREATED_TIMESTAMP = None


def match_full(regex, text):
    match = regex.fullmatch(text)
    if not match:
        raise ValueError(text, regex.pattern)
    return match


def parse_burp_duration(text,
    __regex = re.compile('(?P<number>\d+)(?P<unit>[smhdwn])'),
    __unit_to_seconds = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 7*86400, 'n': 30*86400}
):
    match = match_full(__regex, text)
    return datetime.timedelta(seconds = int(match.group('number')) * __unit_to_seconds[match.group('unit')])


def parse_time_of_day(text,
    __regex = re.compile('((?P<days>[+-]?\d+)[T ]|T?)(?P<hours>[+-]?\d+)(:(?P<minutes>[+-]?\d+)(:(?P<seconds>[+-]?\d+))?)?')
):
    match = match_full(__regex, text)
    kwargs = {key: int(value) for key, value in match.groupdict().items() if value}
    return datetime.timedelta(**kwargs)


Interval = collections.namedtuple('Interval', ('start', 'end'))

def parse_time_of_day_interval(text,
    __regex = re.compile('(?P<start>[0-9:T +-]+)\\.\\.(?P<end>[0-9:T +-]+)')
):
    match = match_full(__regex, text)
    return Interval(*map(parse_time_of_day, match.groups()))


def is_backup_new(backup_path):
    return not os.path.exists(backup_path)


def is_backup_continued(backup_path,
    __interrupted_backup_regex = re.compile('\d{4}-\d\d-\d\d \d\d:\d\d:\d\d: burp\[\d+\] Found interrupted backup.\n'),
):
    if is_backup_new(backup_path):
        return False

    log_filename = os.path.join(backup_path, 'log.gz')
    with gzip.open(log_filename, 'rt') as log_file:
        for line in log_file:
            if __interrupted_backup_regex.fullmatch(line):
                return True

    return False


def read_timestamp(timestamp_filename):
    with open(timestamp_filename, 'rt') as timestamp_file:
        line = timestamp_file.readline().strip('\n')
        index, timestamp_string = line.split(' ', maxsplit = 1)
        timestamp = datetime.datetime.strptime(timestamp_string, '%Y-%m-%d %H:%M:%S')
        return timestamp


def write_timestamp(timestamp_filename, timestamp, index = 0):
    with open(timestamp_filename, 'wt') as timestamp_file:
        timestamp_file.write('{:07} {}\n'.format(index, timestamp.replace(microsecond = 0).isoformat(' ')))


def get_backup_timestamp(backup_path, __new_timestamp = datetime.datetime(1, 1, 1)):
    if is_backup_new(backup_path):
        return __new_timestamp

    timestamp_filename = os.path.join(backup_path, 'timestamp')
    return read_timestamp(timestamp_filename)


def set_created_timestamp(prior_path):
    global CREATED_TIMESTAMP
    created_timestamp_directory, _ = os.path.split(prior_path)
    created_timestamp_filename = os.path.join(created_timestamp_directory, 'created_timestamp')
    if not os.path.exists(created_timestamp_filename):
        os.makedirs(created_timestamp_directory, exist_ok = True)
        write_timestamp(created_timestamp_filename, CURRENT_DATETIME)
    CREATED_TIMESTAMP = read_timestamp(created_timestamp_filename)


Condition = collections.namedtuple('Condition', ('name', 'argument_action', 'call'))


def check_conditions(prior_path, *argument_strings, verbose = False):

    matched_date = None

    def is_new():
        return is_backup_new(prior_path)

    def remote_address():
        return ipaddress.ip_address(os.environ['REMOTE_ADDR'])

    def remote_address_is_private():
        return remote_address().is_private

    def remote_address_in_subnet(subnet_string):
        return remote_address() in ipaddress.ip_network(subnet_string)

    def weekday():
        return matched_date.weekday()

    def init_exceeds(maximum_age_string):
        return is_backup_new(prior_path) and CURRENT_DATETIME > CREATED_TIMESTAMP + parse_burp_duration(maximum_age_string)

    def age_exceeds(maximum_age_string):
        return CURRENT_DATETIME > get_backup_timestamp(prior_path) + parse_burp_duration(maximum_age_string)

    def match_time(interval_string):
        nonlocal matched_date
        interval = parse_time_of_day_interval(interval_string)
        matched_date = (CURRENT_DATETIME - interval.start).date()
        return CURRENT_DATETIME < datetime.datetime.combine(matched_date, datetime.time()) + interval.end

    def negation(condition):
        def result(*args, **kwargs):
            return not condition(*args, **kwargs)
        return result

    def disjunction(condition):
        def result(value_strings):
            value_strings = ','.join(value_strings).split(',')
            for value_string in value_strings:
                if condition(value_string):
                    verbose and print('Matched item: {}'.format(value_string))
                    return True
            return False
        return result

    conditions = (
        Condition(name = 'new', argument_action = 'store_true', call = is_new),
        Condition(name = 'not_new', argument_action = 'store_true', call = negation(is_new)),
        Condition(name = 'continued', argument_action = 'store_true', call = lambda: is_backup_continued(prior_path)),
        Condition(name = 'lan', argument_action = 'store_true', call = remote_address_is_private),
        Condition(name = 'not_lan', argument_action = 'store_true', call = negation(remote_address_is_private)),
        Condition(name = 'subnet', argument_action = 'append', call = disjunction(remote_address_in_subnet)),
        Condition(name = 'not_subnet', argument_action = 'append', call = negation(disjunction(remote_address_in_subnet))),
        # time condition must be processed before any day-related conditions
        # because it may change matched_date
        Condition(name = 'time', argument_action = 'append', call = disjunction(match_time)),
        Condition(name = 'workday', argument_action = 'store_true', call = lambda: weekday() < 5),
        Condition(name = 'holiday', argument_action = 'store_true', call = lambda: weekday() >= 5),
        Condition(name = 'init_exceeds', argument_action = 'store', call = init_exceeds),
        Condition(name = 'age_exceeds', argument_action = 'store', call = age_exceeds),
    )

    if is_backup_new(prior_path):
         set_created_timestamp(prior_path)

    parser = argparse.ArgumentParser()
    for condition in conditions:
        assert '-' not in condition.name
        parser.add_argument('--' + condition.name.replace('_', '-'), action = condition.argument_action)
    parser.add_argument('--stop', action = 'store_true')

    def match_conditions(arguments):
        nonlocal matched_date
        matched_date = CURRENT_DATETIME.date()

        for condition in conditions:
            argument_value = arguments.get(condition.name, None)
            if argument_value in (None, False):
                continue
            condition_arguments = (argument_value,) if argument_value != True else ()
            if not condition.call(*condition_arguments):
                verbose and print('Failed condition: --{} {}'.format(condition.name, argument_value))
                return False
        return True

    for argument_string in argument_strings:
        arguments = vars(parser.parse_args(shlex.split(argument_string)))
        if match_conditions(arguments):
            verbose and print('Matched: {}'.format(argument_string))
            if arguments.get('stop', False):
                return False
            return True

    return False


def main(arguments):
    '''Main function.'''
    if len(arguments) < 7 or '--help' in arguments:
        sys.stderr.write('Usage: <client_name> <prior_path> <data_path> <reserverd1> <reserverd2> <argument_strings...>\n')
        return os.EX_USAGE
    client_name, prior_path, data_path = arguments[1:4]

    argument_strings = arguments[6:]
    conditions_check = check_conditions(prior_path, *argument_strings, verbose = True)
    return {True: os.EX_OK, False: not os.EX_OK}[conditions_check]


if __name__ == "__main__":
    sys.exit(main(sys.argv))


