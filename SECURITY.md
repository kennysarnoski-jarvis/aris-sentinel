# Security policy

Aris Sentinel is a **defensive** tool: it watches a host for an autonomous AI attacker
narrating its own intrusion and alerts or stops it. Bugs in it can cut both ways — a
false negative lets an attacker through, a false positive in `--enforce` kills a
legitimate process. Both are security issues to us.

## Reporting

Please **do not** open a public issue for a bypass, a crash on crafted input, a way to
make the agent kill the wrong process, or anything that leaks data off a host.

Email **support@youraris.com** with:
- what you found and how to reproduce it (a payload or event line is ideal — it will
  be handled as inert evidence, never executed),
- which entry point (Linux agent, Windows agent, Langflow demo, core),
- the commit or version.

You will get an acknowledgement within 3 business days and a fix or a decision within 30.
Credit is given in the changelog unless you ask otherwise.

## In scope

- Detector bypasses that a *narrating* agent could use (encoding tricks the decode stage
  misses, prompt structures that defeat tier 2 while still narrating).
- Anything that makes the agent kill a process it should not (protected-process escapes,
  pid confusion, race conditions in the kill path).
- Detector crashes on crafted input, hangs, or resource exhaustion.
- Data leaving the host that [agent/DATA-HANDLING.md](agent/DATA-HANDLING.md) says does not.
- Weaknesses in the installer / de-branding that expose secrets or the env file.

## Out of scope (known design limits, documented in the README)

- An attacker whose agent does **not narrate at all**. Zero narration is zero signal.
- The Falco package itself being discoverable on the host by deep recon.
- Availability of third-party LLM providers.

## Supported

The `main` branch. Fixes land there; there are no backported releases yet.
