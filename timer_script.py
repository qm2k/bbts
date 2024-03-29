#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''Better Burp Timer Script

Copyright (C) 2017 Marat Khalili <qm2k@yandex.ru>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.'''


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


def now_tz():
    return datetime.datetime.now(datetime.timezone.utc).astimezone()

def replace_time(datetime_, time):
    return datetime.datetime.combine(date = datetime_.date(), time = time).replace(tzinfo = datetime_.tzinfo)


CURRENT_DATETIME = now_tz()


def match_full(regex, text):
    match = regex.fullmatch(text)
    if not match:
        raise ValueError(text, regex.pattern)
    return match


def parse_timezone_offset(text):
    return datetime.datetime.strptime(text, '%z').tzinfo if text != '-' else None


BURP_DURATION_REGEX = re.compile('(?P<number>\d+)(?P<unit>[smhdwn])')

def parse_burp_duration(text,
    __unit_to_seconds = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 7*86400, 'n': 30*86400}
):
    match = match_full(BURP_DURATION_REGEX, text)
    return datetime.timedelta(seconds = int(match.group('number')) * __unit_to_seconds[match.group('unit')])


TIME_OF_DAY_REGEX = re.compile('((?P<days>[+-]?\d+)[T ]|T?)(?P<hours>[+-]?\d+)(:(?P<minutes>[+-]?\d+)(:(?P<seconds>[+-]?\d+))?)?')

def parse_time_of_day(text):
    match = match_full(TIME_OF_DAY_REGEX, text)
    kwargs = {key: int(value) for key, value in match.groupdict().items() if value}
    return datetime.timedelta(**kwargs)


WEEKDAYS = ('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun')

def parse_weekday(text):
    return WEEKDAYS.index(text)


Interval = collections.namedtuple('Interval', ('start', 'end'))

def parse_time_of_day_interval(text,
    __regex = re.compile('(?P<start>[0-9:T +-]+)\\.\\.(?P<end>[0-9:T +-]+)')
):
    match = match_full(__regex, text)
    return Interval(*map(parse_time_of_day, match.groups()))


def read_timestamp(timestamp_filename, __zoneless_length = len('YYYY-mm-dd HH:MM:SS')):
    with open(timestamp_filename, 'rt') as timestamp_file:
        line = timestamp_file.readline().strip('\n')
        index, timestamp_string = line.split(' ', maxsplit = 1)
        if not index.isdigit():
            # probably a variant without backup index
            timestamp_string = line
        timestamp_string, timezone_string = timestamp_string[:__zoneless_length], timestamp_string[__zoneless_length:]
        timestamp = datetime.datetime.strptime(timestamp_string, '%Y-%m-%d %H:%M:%S')
        timezone_string = timezone_string.lstrip().split(' ', maxsplit = 1)[0].replace(':', '')
        if timezone_string == '':
            # presume current timezone
            tzinfo = CURRENT_DATETIME.tzinfo
        elif timezone_string == 'Z':
            tzinfo = datetime.timezone.utc
        elif timezone_string[0] in '+-':
            if len(timezone_string) == 3:
                timezone_string += '00'
            tzinfo = datetime.datetime.strptime(timezone_string, '%z').tzinfo
        else:
            raise ValueError(timezone_string)
        timestamp = timestamp.replace(tzinfo = tzinfo)
        return timestamp


class Backup(object):

    def __get_client_created_timestamp(self):
        directory, _ = os.path.split(self.path)
        filename = os.path.join(directory, '.created')
        if os.path.exists(filename):
            return read_timestamp(filename)
        filename = os.path.join(directory, 'created')
        if not os.path.exists(filename):
            os.makedirs(directory, exist_ok = True)
            with open(filename, 'wt') as file:
                # do not add timezone for reverse backward compatibility
                file.write('{:07} {}\n'.format(0, CURRENT_DATETIME.replace(tzinfo = None, microsecond = 0).isoformat(' ')))
        return read_timestamp(filename)

    def __init__(self, path):
        self.path = path
        self.client_created = self.__get_client_created_timestamp() if self.path and self.is_new() else None

    def is_new(self):
        return not os.path.exists(self.path)

    def is_continued(self,
        __interrupted_regex = re.compile(b'\d{4}-\d\d-\d\d \d\d:\d\d:\d\d: burp\[\d+\] Found interrupted backup.\n'),
    ):
        if self.is_new():
            return False

        resumed_filename = os.path.join(self.path, 'resumed')
        if os.path.exists(resumed_filename):
            return True

        log_filename = os.path.join(self.path, 'log.gz')
        try:
            with gzip.open(log_filename, 'rb') as log_file:
                for line in log_file:
                    if __interrupted_regex.fullmatch(line):
                        return True
        except FileNotFoundError:
            print('Something is fishy: missing {}'.format(log_filename), file = sys.stderr)

        return False

    def get_timestamp(self, __new_timestamp = datetime.datetime(2001, 1, 1, tzinfo = CURRENT_DATETIME.tzinfo)):
        if self.is_new():
            return __new_timestamp

        timestamp_filename = os.path.join(self.path, 'timestamp')
        return read_timestamp(timestamp_filename)

    def init_exceeds(self, maximum_age):
        return self.is_new() and CURRENT_DATETIME > self.client_created + maximum_age

    def age_exceeds(self, maximum_age):
        return CURRENT_DATETIME > self.get_timestamp() + maximum_age


def negation(condition):
    def result(*args, **kwargs):
        return not condition(*args, **kwargs)
    return result

def convert_call(condition, type):
    def result(argument):
        return condition(type(argument))
    return result

def remote_address():
    return ipaddress.ip_address(os.environ['REMOTE_ADDR'])


class Conditions(object):
    def disjunction(self, condition):
        def result(value_strings):
            value_strings = ','.join(value_strings).split(',')
            for value_string in value_strings:
                if condition(value_string):
                    self.verbose and len(value_strings) > 1 and print('Matched item: {}'.format(value_string))
                    return True
            return False
        return result

    def __get_conditions(self):
        Condition = collections.namedtuple('Condition', ('name', 'type', 'call', 'help'))
        return (
            Condition(name = 'new', type = bool,
                call = self.prior_backup.is_new,
                help = 'there is no prior backup'),
            Condition(name = 'continued', type = bool,
                call = self.prior_backup.is_continued,
                help = 'prior backup was interrupted and continued'),
            Condition(name = 'lan', type = bool,
                call = lambda: remote_address().is_private,
                help = 'client ip address is private'),
            Condition(name = 'subnet', type = [ipaddress.ip_network],
                call = lambda subnet: remote_address() in subnet,
                help = 'client ip address belongs to any of specified subnet(s)'),
            # after and time conditions must be processed before any other 
            # day-related conditions because they may change matched_date
            Condition(name = 'after', type = parse_time_of_day,
                call = self.match_date,
                help = '; '.join((
                    'current day starts after specified time-of-day',
                    'affects --(not-)weekday, --(not-)prior-before, --not-time',
                    'incompatible with --time'))),
            Condition(name = 'time', type = [parse_time_of_day_interval],
                call = self.match_time_interval,
                help = '; '.join((
                    'current time belongs to any of specified intervals',
                    'affects --(not-)weekday, --(not-)prior-before, --not-time for ranges outside 0..24',
                    'incompatible with --after'))),
            Condition(name = 'not_time', type = [parse_time_of_day_interval],
                call = self.check_time_interval,
                help = '; '.join((
                    'current time does not belongs to any of specified intervals',
                    'does not affect --(not-)weekday, --(not-)prior-before',
                    'compatible with --after and --time'))),
            Condition(name = 'weekday', type = [parse_weekday],
                call = lambda weekday: self.weekday() == weekday,
                help = 'current day of week is one of specified values'),
            Condition(name = 'init_exceeds', type = parse_burp_duration,
                call = self.prior_backup.init_exceeds,
                help = 'attempts to create initial backup took more than specified duration'),
            Condition(name = 'age_exceeds', type = parse_burp_duration,
                call = self.prior_backup.age_exceeds,
                help = 'prior backup is older than specified duration (or there is no prior backup)'),
            Condition(name = 'prior_before', type = parse_time_of_day,
                call = self.prior_before,
                help = 'prior backup was created before specified time-of-day'),
        )

    def reset(self):
        self.verbose = False
        self.timezone = None
        self.match_date()

    def __init__(self, prior_backup):
        self.prior_backup = prior_backup
        self.conditions = self.__get_conditions()
        self.reset()

    @staticmethod
    def add_arguments(parser):
        metavars = {
            bool: None,
            ipaddress.ip_address: 'IP-ADDRESS',
            ipaddress.ip_network: 'IP-NETWORK',
            parse_time_of_day: 'TIME-OF-DAY',
            parse_time_of_day_interval: 'TIME-OF-DAY..TIME-OF-DAY',
            parse_burp_duration: 'DURATION',
            parse_weekday: 'WEEKDAY',
        }
        for condition in Conditions(Backup(path = None)).__get_conditions():
            name = condition.name
            kwargs = {'help': condition.help}
            if isinstance(condition.type, list):
                [inner_type] = condition.type
                kwargs['metavar'] = metavars[inner_type] + ',...'
                kwargs['action'] = 'append'
            else:
                kwargs['metavar'] = metavars[condition.type]
                kwargs['action'] = 'store_true' if condition.type == bool else 'store'
            if not kwargs['metavar']:
                del kwargs['metavar']

            for invert in (False, True):
                assert '-' not in name
                kwargs['dest'] = name
                option_name = '--' + name.replace('_', '-')
                parser.add_argument(option_name, **kwargs)

                # prepare inversion
                if name in ('after', 'time', 'not_time'):
                    # --not-after is meaningless, --not-time is handled separately
                    break
                name = 'not_' + name
                kwargs['help'] = 'inverted version of {}'.format(option_name)
        return

    def weekday(self):
        return self.matched_date.weekday()

    def prior_before(self, time_of_day):
        return self.matched_date + time_of_day > self.prior_backup.get_timestamp()

    def match_date(self, time_of_day = datetime.timedelta()):
        self.matched_date = replace_time(CURRENT_DATETIME.astimezone(self.timezone) - time_of_day, datetime.time())
        return True

    def match_time_interval(self, interval):
        self.match_date(interval.start)
        return CURRENT_DATETIME < self.matched_date + interval.end

    def check_time_interval(self, interval):
        return self.matched_date + interval.start <= CURRENT_DATETIME < self.matched_date + interval.end

    def match(self, arguments, environment):
        self.reset()

        environment_arguments = {}

        self.verbose = environment['verbose']
        if arguments.pop('verbose', None):
            environment_arguments['verbose'] = True
            self.verbose = True

        self.timezone = environment['timezone']
        utc_offset = arguments.pop('utc_offset', None)
        if utc_offset:
            timezone = parse_timezone_offset(utc_offset)
            environment_arguments['timezone'] = timezone
            self.timezone = timezone
        self.match_date()

        if arguments.get('after', None) and arguments.get('time', None):
            raise ValueError('Arguments --after and --time are not compatible.')

        condition_found = False
        for condition in self.conditions:
            name = condition.name

            call_function = condition.call
            if isinstance(condition.type, list):
                [inner_type] = condition.type
                call_function = self.disjunction(convert_call(call_function, inner_type))
            elif condition.type != bool:
                call_function = convert_call(call_function, condition.type)

            for invert in (False, True):
                # handles both inversion and special case of --not-time
                if name.startswith('not_'):
                    call_function = negation(call_function)

                argument_value = arguments.pop(name, None)
                if argument_value not in (None, False):
                    condition_found = True
                    call_arguments = (argument_value,) if argument_value != True else ()
                    if not call_function(*call_arguments):
                        self.verbose and print('Failed condition: --{} {}'.format(name.replace('_', '-'), argument_value))
                        return False

                # prepare inversion
                if name in ('after', 'time', 'not_time'):
                    # --not-after is meaningless, --not-time is handled separately
                    break
                name = 'not_' + name

        if not condition_found:
            if not environment_arguments:
                raise ValueError('No arguments found.', arguments)
            environment.update(environment_arguments)
            return False

        return True

def create_parser():
    parser = argparse.ArgumentParser(prog = 'timer_arg =', add_help = False, allow_abbrev = False)

    environment_group = parser.add_argument_group(title = 'environment options',
        description = 'acts on a single timer_arg line unless placed on a line of their own')
    environment_group.add_argument('--utc-offset', action = 'store', metavar = 'UTC-OFFSET',
        help = '; '.join((
            'UTC offset of configuration day-of-times',
            'affects --after, --(not-)time, --(not-)weekday, --(not-)prior-before')))
    environment_group.add_argument('--verbose', action = 'store_true',
        help = 'verbose output')

    conditions_group = parser.add_argument_group(title = 'conditions')
    Conditions.add_arguments(conditions_group)

    flow_control_group = parser.add_argument_group(title = 'flow control')
    flow_control_group .add_argument('--stop', action = 'store_true',
        help = 'cancel backup and do not process any more timer_args')

    return parser


def check_conditions(prior_path, *argument_strings):
    parser = create_parser()

    if '--help' in argument_strings:
        print('Better BURP Timer Script (BBTS), version 1.0.2')
        print('usage: <client_name> <prior_path> <data_path> <reserverd1> <reserverd2> <timer_args...> | --help\n')
        parser.print_help()
        print()
        print('metavariable formats:')
        print('  {:22}{}'.format('UTC-OFFSET', '+HHMM or -HHMM or -'))
        print('  {:22}{}'.format('IP-NETWORK', 'See ipaddress.ip_network(...)'))
        print('  {:22}{}'.format('TIME-OF-DAY', TIME_OF_DAY_REGEX.pattern))
        print('  {:22}{}'.format('DURATION', BURP_DURATION_REGEX.pattern))
        print('  {:22}{}'.format('WEEKDAY', '|'.join(WEEKDAYS)))
        sys.exit(os.EX_USAGE)

    prior_backup = Backup(prior_path)
    conditions = Conditions(prior_backup)
    environment = {'verbose': False, 'timezone': None}
    for argument_string in argument_strings:
        arguments = vars(parser.parse_args(shlex.split(argument_string, comments = True)))
        arguments = dict(arguments) # make a copy
        if conditions.match(arguments, environment):
            conditions.verbose and print('Matched: {}'.format(argument_string))
            must_stop = arguments.pop('stop', False)
            # make sure all arguments were handled
            assert not arguments, arguments
            return not must_stop

    environment['verbose'] and print('Nothing matched.')
    return False


def main(arguments):
    '''Main function.'''

    if len(arguments) < 7 or '--help' in arguments:
        check_conditions(None, '--help')
        return

    client_name, prior_path, data_path = arguments[1:4]
    assert os.path.exists(data_path)

    argument_strings = arguments[6:]
    conditions_check = check_conditions(prior_path, *argument_strings)
    return {True: os.EX_OK, False: not os.EX_OK}[conditions_check]


if __name__ == "__main__":
    sys.exit(main(sys.argv))


