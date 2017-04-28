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
    __regex = re.compile('(?P<start>[0-9:T +-]+)\\.\\.(?P<end>[0-9:T +-]+)')
):
    match = match_full(__regex, text)
    return Interval(*map(parse_time_of_day, match.groups()))


def read_timestamp(timestamp_filename):
    with open(timestamp_filename, 'rt') as timestamp_file:
        line = timestamp_file.readline().strip('\n')
        index, timestamp_string = line.split(' ', maxsplit = 1)
        timestamp = datetime.datetime.strptime(timestamp_string, '%Y-%m-%d %H:%M:%S')
        return timestamp


def write_timestamp(timestamp_filename, timestamp, index = 0):
    with open(timestamp_filename, 'wt') as timestamp_file:
        timestamp_file.write('{:07} {}\n'.format(index, timestamp.replace(microsecond = 0).isoformat(' ')))


class Backup(object):

    def __get_client_created_timestamp(self):
        directory, _ = os.path.split(self.path)
        filename = os.path.join(directory, 'created_timestamp')
        if not os.path.exists(filename):
            os.makedirs(directory, exist_ok = True)
            write_timestamp(filename, CURRENT_DATETIME)
        return read_timestamp(filename)

    def __init__(self, path):
        self.path = path
        self.client_created = self.__get_client_created_timestamp() if self.is_new() else None

    def is_new(self):
        return not os.path.exists(self.path)

    def is_continued(self,
        __interrupted_regex = re.compile('\d{4}-\d\d-\d\d \d\d:\d\d:\d\d: burp\[\d+\] Found interrupted backup.\n'),
    ):
        if self.is_new():
            return False

        log_filename = os.path.join(self.path, 'log.gz')
        with gzip.open(log_filename, 'rt') as log_file:
            for line in log_file:
                if __interrupted_regex.fullmatch(line):
                    return True

        return False

    def get_timestamp(self, __new_timestamp = datetime.datetime(1, 1, 1)):
        if self.is_new():
            return __new_timestamp

        timestamp_filename = os.path.join(self.path, 'timestamp')
        return read_timestamp(timestamp_filename)

    def init_exceeds(self, maximum_age_string):
        return self.is_new() and CURRENT_DATETIME > self.client_created + parse_burp_duration(maximum_age_string)

    def age_exceeds(self, maximum_age_string):
        return CURRENT_DATETIME > self.get_timestamp() + parse_burp_duration(maximum_age_string)


class ConditionsArgumentsMatch(object):

    def reset(self):
        self.matched_date = CURRENT_DATETIME.date()

    def __init__(self, prior_backup, verbose = False):
        self.prior_backup = prior_backup
        self.verbose = verbose
        self.reset()

    def matched_datetime(self, time_of_day):
        return datetime.datetime.combine(self.matched_date, datetime.time()) + time_of_day

    def weekday(self):
        return self.matched_date.weekday()

    def prior_before(self, time_of_day_string):
        return self.matched_datetime(parse_time_of_day(time_of_day_string)) > self.prior_backup.get_timestamp()

    def match_date(self, after_string):
        self.matched_date = (CURRENT_DATETIME - parse_time_of_day(after_string)).date()
        return True

    def match_time(self, interval_string):
        interval = parse_time_of_day_interval(interval_string)
        self.matched_date = (CURRENT_DATETIME - interval.start).date()
        return CURRENT_DATETIME < self.matched_datetime(interval.end)

    def negation(self, condition):
        def result(*args, **kwargs):
            return not condition(*args, **kwargs)
        return result

    def disjunction(self, condition):
        def result(value_strings):
            value_strings = ','.join(value_strings).split(',')
            for value_string in value_strings:
                if condition(value_string):
                    self.verbose and print('Matched item: {}'.format(value_string))
                    return True
            return False
        return result


def negation(condition):
    def result(*args, **kwargs):
        return not condition(*args, **kwargs)
    return result

def remote_address():
    return ipaddress.ip_address(os.environ['REMOTE_ADDR'])

def remote_address_is_private():
    return remote_address().is_private

def remote_address_in_subnet(subnet_string):
    return remote_address() in ipaddress.ip_network(subnet_string)


Condition = collections.namedtuple('Condition', ('name', 'argument_action', 'call'))


def check_conditions(prior_path, *argument_strings, verbose = False):

    prior_backup = Backup(prior_path)
    condition_arguments_match = ConditionsArgumentsMatch(prior_backup, verbose)

    conditions = (
        Condition(name = 'new', argument_action = 'store_true', call = prior_backup.is_new),
        Condition(name = 'not_new', argument_action = 'store_true', call = negation(prior_backup.is_new)),
        Condition(name = 'continued', argument_action = 'store_true', call = prior_backup.is_continued),
        Condition(name = 'lan', argument_action = 'store_true', call = remote_address_is_private),
        Condition(name = 'not_lan', argument_action = 'store_true', call = negation(remote_address_is_private)),
        Condition(name = 'subnet', argument_action = 'append', call = condition_arguments_match.disjunction(remote_address_in_subnet)),
        Condition(name = 'not_subnet', argument_action = 'append', call = negation(condition_arguments_match.disjunction(remote_address_in_subnet))),
        # after and time conditions must be processed before any other 
        # day-related conditions because they may change matched_date
        Condition(name = 'after', argument_action = 'store', call = condition_arguments_match.match_date),
        Condition(name = 'time', argument_action = 'append', call = condition_arguments_match.disjunction(condition_arguments_match.match_time)),
        Condition(name = 'workday', argument_action = 'store_true', call = lambda: condition_arguments_match.weekday() < 5),
        Condition(name = 'holiday', argument_action = 'store_true', call = lambda: condition_arguments_match.weekday() >= 5),
        Condition(name = 'init_exceeds', argument_action = 'store', call = prior_backup.init_exceeds),
        Condition(name = 'age_exceeds', argument_action = 'store', call = prior_backup.age_exceeds),
        Condition(name = 'prior_before', argument_action = 'store', call = condition_arguments_match.prior_before),
    )

    parser = argparse.ArgumentParser()
    for condition in conditions:
        assert '-' not in condition.name
        parser.add_argument('--' + condition.name.replace('_', '-'), action = condition.argument_action)
    parser.add_argument('--stop', action = 'store_true')

    def match_conditions(arguments):
        condition_arguments_match.reset()

        if arguments.get('after', None) and arguments.get('time', None):
            raise ValueError('Arguments --after and --time are not compatible.')

        argument_found = False
        for condition in conditions:
            argument_value = arguments.get(condition.name, None)
            if argument_value in (None, False):
                continue
            argument_found = True

            condition_arguments = (argument_value,) if argument_value != True else ()
            if not condition.call(*condition_arguments):
                verbose and print('Failed condition: --{} {}'.format(condition.name, argument_value))
                return False

        if not argument_found:
            raise ValueError('No arguments found.')

        return True

    for argument_string in argument_strings:
        arguments = vars(parser.parse_args(shlex.split(argument_string, comments = True)))
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


