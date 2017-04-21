#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''The better burp timer script.'''


import os
import sys

import datetime
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


def main(arguments):
    '''Main function.'''
    if len(arguments) < 6 or '--help' in arguments:
        sys.stderr.write('Usage: <client_name> <latest_path> <client_path> <reserverd1> <reserverd2>\n')
        return os.EX_USAGE

    print('arguments:', arguments)

    command = list(arguments)
    command[0] = '/usr/share/burp/scripts/timer_script'
    command[7:] = arguments[7:]
    print('command:', command)
    result = subprocess.run(command)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv))


