# A better timer script for [BURP](http://burp.grke.org/)

## Usage

Only `timer_script.py` is needed for production, other files are used for tests and development.
Put timer_script.py anywhere on your server and specify it in `timer_script` line in server configuration, like:

`timer_script = /opt/local/bin/timer_script.py`

Then specify necessary backup conditions in `timer_arg` lines, e.g.:

`timer_arg = --age-exceeds 20h`

You can specify multiple conditions per line.
All conditions on any `timer_arg` line must be met for backup to occur.
Special `--stop` condition stops processing of further lines.

Run script without parameters to see all supported conditions.
