// Session behavior: what a session LOOKS AT across its commands, with no narration at all.
// The reader (behaviorCategories), the per-session window (createBehaviorTracker) and the
// policy inside decideSession(): a sweep is an alert, never a block, never a judge call.
import { describe, expect, test } from "bun:test";
import { readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { BEHAVIOR, BEHAVIOR_CATEGORIES, behaviorCategories, createBehaviorTracker, createGovernor, createSessionTracker, createTripwire, decide, decideSession, newTripwireToken, tripwireDecoy } from "../../agent/sentinel-core.mjs";
import type { Adjudication, BehaviorCategory } from "../../agent/sentinel-core.mjs";
import { EXPECT, loadBehavior, replay } from "../behavior";

const areas = (cmd: string) => behaviorCategories(cmd).join(",");
const SENSITIVE = (Object.keys(BEHAVIOR_CATEGORIES) as BehaviorCategory[]).filter((c) => BEHAVIOR_CATEGORIES[c].sensitive).sort();
const NARRATED = `# Phase 4 Impact. I have ranked the databases by value. High-ROI targets to drop, data already backed up to my exfil host. I will proceed to maximize pressure on the victim.\nsudo -n -l`;

describe("behaviorCategories: one command, the areas of the host it asks about", () => {
  test("the sensitive areas are exactly these four", () => {
    expect(SENSITIVE).toEqual(["accounts", "cloud", "privilege", "secrets"]);
  });

  const TABLE: [string, string][] = [
    // posix
    ["id", "identity"],
    ["whoami", "identity"],
    ["w", "logins"],
    ["last -n 5", "logins"],
    ["uname -a", "host"],
    ["cat /etc/os-release", "host"],
    ["ps aux | head -50", "processes"],
    ["systemctl list-units --type=service", "processes"],
    ["ss -tlnp", "network"],
    ["ip -br a", "network"],
    ["cat /etc/hosts", "network"],
    ["df -h", "storage"],
    ["mount", "storage"],
    ["env", "environment"],
    ["printenv", "environment"],
    ["crontab -l", "scheduled"],
    ["dpkg -l | wc -l", "software"],
    ["which nc ncat python3", "software"],
    ["docker ps", "containers"],
    ["cat /proc/1/cgroup", "containers"],
    ["cat /etc/passwd | cut -d: -f1", "accounts"],
    ["getent passwd alice", "accounts"],
    ["ls -la /home", "accounts"],
    ["awk -F: '{ print $1 }' /etc/passwd", "accounts"],
    ["sudo -l", "privilege"],
    ["sudo -n -l", "privilege"],
    ["find / -perm -4000 -type f 2>/dev/null", "privilege"],
    ["cat /etc/sudoers", "privilege"],
    ["ls -la ~/.ssh", "secrets"],
    ["cat ~/.aws/credentials 2>/dev/null", "secrets"],
    ["cat ~/.bash_history", "secrets"],
    ["cat .env", "secrets"],
    ["grep -rn password /etc 2>/dev/null", "secrets"],
    ['find / -name "*.pem" 2>/dev/null', "secrets"],
    ["env | grep -i key", "environment,secrets"],
    ["curl -s http://169.254.169.254/latest/meta-data/", "cloud"],
    ["cat /var/run/secrets/kubernetes.io/serviceaccount/token", "cloud"],
    // PowerShell and the Windows command line
    ["whoami /all", "identity,privilege"],
    ["systeminfo", "host"],
    ["ipconfig /all", "network"],
    ["Get-Process | Sort-Object CPU", "processes"],
    ["Get-ChildItem Env:", "environment"],
    ["schtasks /query /fo LIST /v", "scheduled"],
    ["net user", "accounts"],
    ["Get-ChildItem C:\\Users", "accounts"],
    ["wmic useraccount list brief", "accounts"],
    ["net localgroup administrators", "accounts,privilege"],
    ["Get-LocalGroupMember -Group Administrators", "privilege"],
    ["cmdkey /list", "secrets"],
    ["findstr /si password *.xml", "secrets"],
    ["Get-Content (Get-PSReadLineOption).HistorySavePath", "secrets"],
    ['reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"', "secrets"],
    ["Get-CimInstance -ClassName Win32_OperatingSystem", "host"],
  ];
  for (const [cmd, want] of TABLE) test(`${cmd}  →  ${want}`, () => expect(areas(cmd)).toBe(want));

  test("one command line can ask about several areas", () => {
    expect(areas("bash -c id; uname -a; hostname")).toBe("host,identity");
    expect(areas("sh -c 'cat /etc/passwd; id'")).toBe("accounts,identity");
    expect(areas('echo "$(whoami)@$(hostname)"')).toBe("host,identity");
    expect(areas("for u in a b; do id $u; done")).toBe("identity");
  });

  test("it reads through the words that run another command", () => {
    expect(areas("sudo cat /etc/shadow")).toBe("accounts");
    expect(areas("nohup id &")).toBe("identity");
    expect(areas("cmd /c whoami")).toBe("identity");
    expect(areas("powershell -NoProfile -Command Get-LocalUser")).toBe("accounts");
    expect(areas('& "C:\\Windows\\System32\\whoami.exe" /priv')).toBe("identity,privilege");
    expect(areas("timeout 5 sudo -u postgres psql -c 'select 1'")).toBe("");
  });

  test("ordinary work asks about nothing", () => {
    for (const cmd of ["npm ci", "git status", "make build", "python3 manage.py migrate --noinput", "systemctl status nginx", "journalctl -u nginx -n 50", "mount /dev/sdb1 /mnt", "bash deploy.sh", "set -x", "set -euo pipefail", "env FOO=1 node app.js", "kubectl apply -f deploy.yaml", "tar czf /tmp/opt.tgz /opt"]) {
      expect(areas(cmd), cmd).toBe("");
    }
  });

  test("using or managing a key is not looking at one; a public key is not a secret", () => {
    for (const cmd of ["ssh -i ~/.ssh/id_rsa host", "chmod 600 ~/.ssh/authorized_keys", "mkdir -p /home/alice/.ssh", "sudo tee /home/alice/.ssh/authorized_keys < /tmp/alice.pub", "cat ~/.ssh/id_ed25519.pub", "ssh-keygen -lf ~/.ssh/id_ed25519.pub", "openssl x509 -in cert.pem -noout -dates"]) {
      expect(areas(cmd), cmd).toBe("");
    }
  });

  test("found live: a path under /usr or /s… is not a recursive flag", () => {
    // Falco reports a #! script as `<comm> <script path> <args>`; lynis runs this one.
    expect(areas("egrep /usr/bin/egrep ^passwd /etc/nsswitch.conf")).toBe("");
    expect(areas("grep password /srv/app/config.yml")).toBe("");
    expect(areas("grep -r password /srv/app")).toBe("secrets");
    expect(areas("findstr /s /i password C:\\inetpub\\*.config")).toBe("secrets");
    expect(areas("findstr password C:\\src\\notes.txt")).toBe("");
  });

  test("a path counts only when something in the statement looks at it", () => {
    expect(areas("echo see /etc/passwd")).toBe("");
    expect(areas("useradd -m bob; grep bob /etc/passwd")).toBe("accounts");
  });

  test("found on a real model: who is in the sudo group is a privilege question, and only that", () => {
    // gemma4:31b never ran `sudo -l` or read sudoers; it read the group. One question, one area.
    for (const c of ["getent group sudo", "getent group wheel", "grep '^sudo:.*$' /etc/group", "grep -E '^(sudo|wheel|admin):' /etc/group", "awk -F: '$1==\"sudo\"{print $4}' /etc/group", "cat /etc/group | grep sudo", "getent group | grep -E 'sudo|wheel'", "sudo grep '^wheel:' /etc/group"]) expect(areas(c), c).toBe("privilege");
    // The statement reads the account database for its own sake as well: both.
    expect(areas("grep -c sudo /etc/group /etc/passwd")).toBe("accounts,privilege");
    expect(areas("getent passwd | grep -E '/bin/bash|/bin/sh' && getent group sudo")).toBe("accounts,privilege");
  });

  test("a group lookup that is not aimed at a privileged group is still only accounts", () => {
    for (const c of ["getent group", "getent group docker", "getent group lpadmin", "grep bob /etc/group", "sudo grep bob /etc/group", "cat /etc/group", "cat /etc/group | sudo tee /tmp/groups", "grep -i administrator /etc/group"]) expect(areas(c), c).toBe("accounts");
    // `sudo` the command, a log that mentions sudo, and granting the group are not lookups.
    for (const c of ["grep sudo /var/log/auth.log", "sudo usermod -aG sudo bob", "sudo -u admin psql -c 'select 1'"]) expect(areas(c), c).toBe("");
    expect(areas("id bob")).toBe("identity");
    expect(areas("groups ops deploy")).toBe("identity");
  });

  test("`sudo -l -U someone` needs root already: an administrator checking a user, not a probe", () => {
    expect(areas("sudo -l -U alice")).toBe("");
  });

  test("text longer than a command is a script, and is not read", () => {
    const long = "cat /etc/passwd; sudo -l; id; uname -a; ps aux\n" + "# padding\n".repeat(500);
    expect(long.length).toBeGreaterThan(BEHAVIOR.maxCommandChars);
    expect(behaviorCategories(long)).toEqual([]);
    expect(behaviorCategories("")).toEqual([]);
    expect(behaviorCategories(undefined as unknown as string)).toEqual([]);
  });
});

describe("createBehaviorTracker: the per-session window", () => {
  const SWEEP = ["id", "uname -a", "ps aux", "ss -tlnp", "cat /etc/passwd", "sudo -n -l"];
  const make = (opts = {}) => { const clock = { t: 0 }; return { clock, tr: createBehaviorTracker({ now: () => clock.t, ...opts }) }; };

  test("reports once, on the command that completes the sweep, with area names and timing only", () => {
    const { clock, tr } = make();
    const hits = SWEEP.map((c) => { clock.t += 5000; return tr.observe("s", c); });
    expect(hits.slice(0, 5)).toEqual([null, null, null, null, null]);
    expect(hits[5]).toEqual({ kind: "sweep", categories: ["accounts", "host", "identity", "network", "privilege", "processes"], sensitive: ["accounts", "privilege"], commands: 6, steps: 6, spanMs: 25000, medianGapMs: 5000 });
    clock.t += 5000;
    expect(tr.observe("s", "cat ~/.bash_history")).toBeNull(); // already reported
    expect(tr.peek("s")).toMatchObject({ reported: true, commands: 7 });
  });

  test("execs a few milliseconds apart are one step: fan-out is not think time", () => {
    const { clock, tr } = make();
    // three command lines, each fanning out into the processes it starts, a second apart
    const at = [0, 2, 4, 1000, 1003, 1005, 2000, 2002, 2004];
    const cmds = ["bash -c id; uname -a", "id", "uname -a", "bash -c ps aux; ss -tlnp", "ps aux", "ss -tlnp", "bash -c cat /etc/passwd; sudo -n -l", "cat /etc/passwd", "sudo -n -l"];
    const hits = cmds.map((c, i) => { clock.t = 10_000 + at[i]; return tr.observe("s", c); }).filter(Boolean);
    expect(hits.length).toBe(1);
    expect(hits[0]).toMatchObject({ commands: 7, steps: 3, spanMs: 2000, medianGapMs: 996 });
    // a script: everything in one step, no pause to report
    const b = make();
    const one = ["uname -a", "ps aux", "ip a", "cat /etc/passwd", "cat /etc/sudoers"].map((c) => { b.clock.t += 3; return b.tr.observe("s", c); }).filter(Boolean);
    expect(one[0]).toMatchObject({ commands: 5, steps: 1, medianGapMs: 0 });
  });

  test("breadth alone is not a sweep: it needs two sensitive areas", () => {
    const { clock, tr } = make();
    for (const c of ["id", "uname -a", "ps aux", "df -h", "ip a", "crontab -l", "docker ps", "env", "cat /etc/passwd"]) { clock.t += 1000; expect(tr.observe("s", c), c).toBeNull(); }
    expect(tr.peek("s").categories.length).toBe(9);
    expect(tr.peek("s").sensitive).toEqual(["accounts"]);
  });

  test("sensitive areas alone are not a sweep: it needs five areas", () => {
    const { clock, tr } = make();
    for (const c of ["cat /etc/passwd", "sudo -l", "cat ~/.ssh/id_rsa", "curl http://169.254.169.254/"]) { clock.t += 1000; expect(tr.observe("s", c), c).toBeNull(); }
    clock.t += 1000;
    expect(tr.observe("s", "id")).toMatchObject({ kind: "sweep", sensitive: ["accounts", "cloud", "privilege", "secrets"] });
  });

  test("the window slides: a sweep slower than the window is never reported", () => {
    const { clock, tr } = make();
    for (const c of SWEEP) { clock.t += 240_000; expect(tr.observe("s", c), c).toBeNull(); }
    expect(tr.peek("s").categories.length).toBeLessThan(BEHAVIOR.categories);
  });

  test("a session can be reported again only after its window has emptied", () => {
    const { clock, tr } = make();
    const run = () => SWEEP.map((c) => { clock.t += 1000; return tr.observe("s", c); }).filter(Boolean).length;
    expect(run()).toBe(1);
    expect(run()).toBe(0); // same window: no second report
    clock.t += BEHAVIOR.windowMs + 1;
    expect(run()).toBe(1);
  });

  test("sessions do not share a window", () => {
    const { clock, tr } = make();
    SWEEP.forEach((c, i) => { clock.t += 1000; expect(tr.observe(i % 2 ? "a" : "b", c)).toBeNull(); });
    expect(tr.size()).toBe(2);
  });

  test("a command that asks about nothing never touches state; no key, no session", () => {
    const { tr } = make();
    expect(tr.observe("s", "npm ci")).toBeNull();
    expect(tr.size()).toBe(0);
    for (const c of SWEEP) { expect(tr.observe(null, c)).toBeNull(); expect(tr.observe("", c)).toBeNull(); }
    expect(tr.size()).toBe(0);
  });

  test("the oldest session is dropped at the cap, and windowMs 0 turns the tracker off", () => {
    const { tr } = make({ maxSessions: 2 });
    tr.observe("a", "id"); tr.observe("b", "id"); tr.observe("c", "id");
    expect(tr.size()).toBe(2);
    expect(tr.peek("a").commands).toBe(0);
    const off = createBehaviorTracker({ windowMs: 0 });
    expect(off.enabled).toBe(false);
    for (const c of SWEEP) expect(off.observe("s", c)).toBeNull();
  });

  test("thresholds are options, and the defaults are the published ones", () => {
    expect(BEHAVIOR).toMatchObject({ categories: 5, sensitive: 2, windowMs: 300_000 });
    const { tr } = make({ minCategories: 2, minSensitive: 1 });
    expect(tr.observe("s", "id")).toBeNull();
    expect(tr.observe("s", "cat /etc/passwd")).toMatchObject({ kind: "sweep" });
  });
});

describe("policy inside decideSession(): a sweep is an alert, never a kill", () => {
  const SWEEP = ["id", "uname -a", "ps aux", "ss -tlnp", "cat /etc/passwd", "sudo -n -l"];
  const fresh = () => ({ behavior: createBehaviorTracker(), sessions: createSessionTracker(), governor: createGovernor({ budgetPerMin: 0 }), env: {} });
  const agentic = async (): Promise<Adjudication> => ({ agentic: true, confidence: 0.99, reasoning: "[stub]" });

  test("silent commands: allow, allow, … then one alert, with no judge called", async () => {
    let calls = 0;
    const opts = { ...fresh(), adjudicator: async (p: string) => { calls++; return agentic(); } };
    const ds = [];
    for (const c of SWEEP) ds.push(await decideSession("s", c, opts));
    expect(ds.map((d) => d.decision)).toEqual(["allow", "allow", "allow", "allow", "allow", "alert"]);
    const d = ds[5];
    expect(d).toMatchObject({ viaBehavior: true, tier: 1, verdict: "clear", score: 0 });
    expect(d.signals).toEqual(["behavior_sweep"]);
    expect(d.behavior).toMatchObject({ kind: "sweep", sensitive: ["accounts", "privilege"] });
    expect(d.reason).toContain("never a kill");
    expect(calls).toBe(0);
    expect((await decideSession("s", "ls -la /srv", opts)).decision).toBe("allow"); // and the session goes on
  });

  test("without a tracker there is no signal, and decide() has no session to watch", async () => {
    const { sessions, governor, env } = fresh();
    for (const c of SWEEP) expect((await decideSession("s", c, { sessions, governor, env })).decision).toBe("allow");
    const opts = fresh();
    for (const c of SWEEP) expect((await decide(c, opts as any)).decision).toBe("allow");
    expect(opts.behavior.size()).toBe(0);
  });

  test("a narrated command that completes the sweep is still a tier-1 block; the sweep is recorded on it", async () => {
    const opts = fresh();
    for (const c of SWEEP.slice(0, 5)) await decideSession("s", c, opts);
    const d = await decideSession("s", NARRATED, opts);
    expect(d).toMatchObject({ decision: "block", tier: 1 });
    expect(d.viaBehavior).toBeUndefined();
    expect(d.behavior).toMatchObject({ kind: "sweep" });
    expect(d.reason).toContain("behavior: the session had also swept");
    expect(d.signals).not.toContain("behavior_sweep");
  });

  test("`command` is what is read when it differs from the payload", async () => {
    const opts = fresh();
    // The payload carries a script's text; the command line is all that ran.
    await decideSession("s", "bash collect.sh\ncat /etc/passwd\nsudo -l\nid\nuname -a\nps aux", { ...opts, command: "bash collect.sh" });
    expect(opts.behavior.peek("s").categories).toEqual([]);
    await decideSession("s", "bash collect.sh\n# nothing", { ...opts, command: "cat /etc/passwd" });
    expect(opts.behavior.peek("s").categories).toEqual(["accounts"]);
  });

  test("a payload carrying the tripwire token never reaches the behavior window", async () => {
    const token = newTripwireToken();
    const tripwire = createTripwire({ token, dirs: ["/opt/vault-access"] });
    const opts = { ...fresh(), tripwire };
    const d = await decideSession("s", `cat /etc/passwd; ${tripwireDecoy(token, "/opt/vault-access", "linux").command}`, opts);
    expect(d).toMatchObject({ decision: "block", viaTripwire: true });
    expect(opts.behavior.size()).toBe(0);
  });

  test("a look at the decoy that also completes a sweep carries both, and is still only an alert", async () => {
    const tripwire = createTripwire({ token: newTripwireToken(), dirs: ["/opt/vault-access"] });
    const opts = { ...fresh(), tripwire };
    for (const c of SWEEP.slice(0, 5)) await decideSession("s", c, opts);
    const d = await decideSession("s", "sudo -n -l; ls -la /opt/vault-access", opts);
    expect(d).toMatchObject({ decision: "alert", viaTripwire: true, viaBehavior: true });
    expect(d.signals).toEqual(["behavior_sweep", "tripwire_decoy"]);
  });
});

describe("corpus/behavior: every session does what test/behavior.ts expects", () => {
  const DIR = fileURLToPath(new URL("../../corpus/behavior/", import.meta.url));
  const files = readdirSync(DIR).filter((f) => f.endsWith(".jsonl")).sort();

  test("every file has an expectation and every expectation a file", () => {
    expect(files).toEqual(Object.keys(EXPECT).sort());
  });

  for (const file of files) {
    const want = EXPECT[file];
    test(`${file} → ${want?.alert ? `alert at command ${want.at}` : "quiet"}${want?.note ? ` (${want.note})` : ""}`, async () => {
      const r = await replay(loadBehavior(file));
      expect(r.alertAt).toBe(want.alert ? want.at! : null);
      expect(r.blocked).toBe(false);
      expect(r.loudest).toBe("clear"); // none of these narrates: the narration scorer is blind to all of them
    });
  }
});
