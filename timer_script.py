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
    __regex = re.compile('(?P<start>[0-9:T +-]*[0-9T ])(/|--)(?P<end>[0-9:T +-]+)')
):
    match = match_full(__regex, text)
    return Interval(
        start = parse_time_of_day(match.group('start')),
        end = parse_time_of_day(match.group('end')))


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


def match_argument_strings(prior_path, *argument_strings, verbose = False):

    def remote_address():
        return ipaddress.ip_address(os.environ['REMOTE_ADDR'])

    def remote_address_is_private():
        return remote_address().is_private

    def remote_address_in_subnet(subnet_string):
        return remote_address() in ipaddress.ip_network(subnet_string)

    def weekday():
        return CURRENT_DATETIME.weekday()

    def age_exceeds(maximum_age_string):
        return CURRENT_DATETIME > get_backup_timestamp(prior_path) + parse_burp_duration(maximum_age_string)

    def current_time_in(interval_string):
        current_time_of_day = CURRENT_DATETIME - datetime.datetime.combine(CURRENT_DATETIME.date(), datetime.time())
        interval = parse_time_of_day_interval(interval_string)
        return interval.start <= current_time_of_day < interval.end

    def negation(condition):
        def result(*args, **kwargs):
            return not condition(*args, **kwargs)
        return result

    def conjunction(condition):
        def result(value_strings):
            value_strings = ','.join(value_strings).split(',')
            for value_string in value_strings:
                if condition(value_string):
                    verbose and print('Matched item: {}', value_string)
                    return True
            return False
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
        Condition(name = 'lan', argument_action = 'store_true', call = remote_address_is_private),
        Condition(name = 'not_lan', argument_action = 'store_true', call = negation(remote_address_is_private)),
        Condition(name = 'subnet', argument_action = 'append', call = disjunction(remote_address_in_subnet)),
        Condition(name = 'not_subnet', argument_action = 'append', call = negation(disjunction(remote_address_in_subnet))),
        Condition(name = 'workday', argument_action = 'store_true', call = lambda: weekday() < 5),
        Condition(name = 'holiday', argument_action = 'store_true', call = lambda: weekday() >= 5),
        Condition(name = 'age_exceeds', argument_action = 'store', call = age_exceeds),
        Condition(name = 'time', argument_action = 'append', call = disjunction(current_time_in)),
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
                verbose and print('Failed condition: --{} {}'.format(condition.name, argument_value))
                return False
        return True

    for argument_string in argument_strings:
        if match_conditions(vars(parser.parse_args(shlex.split(argument_string)))):
            verbose and print('Matched: {}'.format(argument_string))
            return True

    return False


def is_backup_necessary(prior_path, *argument_strings, verbose = False):
    if not os.path.exists(prior_path):
        return True

    if is_backup_continued(prior_path):
        return True

    return match_argument_strings(prior_path, *argument_strings, verbose = verbose)


def main(arguments):
    '''Main function.'''
    if len(arguments) < 7 or '--help' in arguments:
        sys.stderr.write('Usage: <client_name> <prior_path> <data_path> <reserverd1> <reserverd2> <argument_strings...>\n')
        return os.EX_USAGE
    client_name, prior_path, data_path = arguments[1:4]
    argument_strings = arguments[6:]

    return os.EX_OK if is_backup_necessary(prior_path, *argument_strings, verbose = True) else not os.EX_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv))


