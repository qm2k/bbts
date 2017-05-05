Dear all,

I've created a [better BURP timer script](https://github.com/qm2k/bbts) that I'd like to share with public. It is available under AGPL-3.0, same license as for BURP. It allows one to create pretty sophisticated backup schemes without programming.

My main requirements were:
- gradually fall-back to less preferred methods if backup cannot be completed in a preferred way;
- treat new and continued (interrupted and later resumed) backups specially.

## FEATURES
In current version backup can be made dependent on:
- client IP-address (LAN/WAN, specific subnet);
- absence of prior backup (initial backup);
- time since client was acquainted (for initial backup);
- prior backup being continued;
- age of prior backup;
- time-of-day of prior backup;
- current time-of-day;
- current day-of-week;
- any combination of the above.

UTC offset different from one on the server can be specified.

## REQUIREMENTS

One current catch is pretty high version of Python3 required: I've only tested it under Python 3.5.2 in Ubuntu Xenial, most likely it won't work with older Python3 versions. If you only have older version in your distribution and the script doesn't work, please reply with your version of Python and the error messages you see, I'll try to correct it.

I sincerely hope there're no supported distributions left that only have Python2, but if you have such system please contact me too.

No additional libraries are required (at least in my system).

## INSTALLATION

There is no installation. Just download script from https://raw.githubusercontent.com/qm2k/bbts/master/timer_script.py and drop it wherever you want, then specify it in `timer_script =` line of burp server configuration or clientconfdir files, and its arguments in `timer_arg =` lines, e.g.:

    timer_script = /opt/local/bin/timer_script.py
    timer_arg = --age-exceeds 20h

## CONFIGURATION

Add as many `timer_arg =` lines as you want to BURP configuration or clinetconfdir files, each line containing full set of conditions for backup. For each line, backup happens if all conditions are met, otherwise next `timer_arg =` line is considered. Special `--stop` argument cancels backup if all conditions on the line are met.

## EXAMPLES

- Never backup over a known GPRS subnet (when client uses tethering; put this line above others):
```
timer_arg =  --subnet 213.87.128.0/19  --stop
```
- Unconditionally restart continued backups right away (but previous rule would still apply):
```
timer_arg =  --continued
```
- Start doing day's backups after 7PM and over the LAN, but fallback to WAN after 3 days:
```
timer_arg =  --prior-before 12  --lan  --after 19
timer_arg =  --age-exceeds 3d
```

See [examples](https://github.com/qm2k/bbts/tree/master/examples) folder for more.

--

With Best Regards,<br>
Marat Khalili
