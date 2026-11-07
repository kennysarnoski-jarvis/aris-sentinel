# Server hardening checklist (defender's view)

What we look for during a quarterly review, grouped by the attacker phase it defends against.

## Persistence
- [ ] No unexpected systemd units, cron entries, or scheduled tasks since the last baseline
- [ ] `/etc/ld.so.preload` is empty
- [ ] authorized_keys files match the inventory

## Lateral movement
- [ ] SSH agent forwarding disabled on bastions
- [ ] Service accounts cannot log in interactively

## Credential access
- [ ] No plaintext secrets in config directories (run the scanner)
- [ ] IMDSv2 required on every instance

## Exfiltration
- [ ] Egress allowlist in place; DNS logged
- [ ] Large outbound transfers alert the on-call

Anything unchecked becomes a ticket, ranked by the severity of what it would allow.
