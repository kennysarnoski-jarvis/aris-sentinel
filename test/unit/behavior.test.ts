// Session behavior: what a session LOOKS AT across its commands, with no narration at all.
// The reader (behaviorCategories), the per-session window (createBehaviorTracker) and the
// policy inside decideSession(): a sweep is an alert, never a block, never a judge call.
import { describe, expect, test } from "bun:test";
import { readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { BEHAVIOR, BEHAVIOR_CATEGORIES, BEHAVIOR_SERVICE, behaviorCategories, behaviorOrigin, behaviorService, behaviorServices, createBehaviorTracker, createGovernor, createSessionTracker, createTripwire, decide, decideSession, newTripwireToken, observeBehavior, tripwireDecoy } from "../../agent/sentinel-core.mjs";
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

// Found on a real host (2026-11-21): a sensor reports an exec as the program and its arguments
// joined by spaces, with the quotes gone. Read as shell text, an argument that holds `||`, `|`,
// `(` or `;` was cut there: real surveys were missed, and commands that never ran were counted.
describe("one process is one command (exec), not shell text", () => {
  const exec = (cmd: string) => behaviorCategories(cmd, { exec: true }).join(",");

  test("an argument's own operators do not cut the command", () => {
    expect(exec(`awk -F: $3>=1000 || $3==0 {print $1":"$3":"$7} /etc/passwd`)).toBe("accounts");
    expect(exec(`awk -F: $3>=1000 || $1=="root" {print $1":"$3":"$6":"$7} /etc/passwd`)).toBe("accounts");
    expect(exec("grep -rniE api[_-]?key|secret|password /tmp/w")).toBe("secrets");
    expect(exec("grep -rniE foo|password /srv/app")).toBe("secrets");
    expect(exec("grep -E ^(sudo|wheel|admin): /etc/group")).toBe("privilege");
    expect(exec("grep -hv ^\\s*# /etc/sudoers /etc/sudoers.d/dev")).toBe("privilege");
    // and the same text read as a shell line is what it always was (the corpus is shell text)
    expect(areas(`awk -F: $3>=1000 || $3==0 {print $1":"$3":"$7} /etc/passwd`)).toBe("");
    expect(areas("grep -rniE foo|password /srv/app")).toBe("");
  });

  test("text inside an argument is not a command: a commit message, a log line, a request body", () => {
    const mentions = [
      "git commit -m docs: the audit steps (id; uname -a; ps aux; cat /etc/passwd; sudo -l) and what each shows",
      "logger -t deploy runbook step 3 done: ss -tlnp && cat /etc/passwd | wc -l",
      `curl -fsS -X POST -d {"title":"host check","body":"ran id; cat /etc/shadow; sudo -n -l"} https://tickets.example/api/issues`,
      "psql -c select count(*) from jobs where state = 'failed'; -- then run: sudo -l",
      "notify-send deploy finished: ran id; cat /etc/shadow; sudo -n -l",
    ];
    for (const m of mentions) expect(exec(m)).toBe("");
    // The limit that remains: for a command that reads files, a path among its arguments counts as
    // read, and with the quotes gone a search PATTERN that names a path looks the same as a file.
    expect(exec("grep -n cat /etc/shadow notes.md")).toBe("accounts");
    // read as shell text, the first one is a five-area sweep from a single line: the false positive this removes
    expect(areas(mentions[0])).toBe("accounts,host,identity,privilege,processes");
    expect(exec("grep -Ev :(/usr/sbin/nologin|/bin/false|/sbin/nologin)$")).toBe("");
    expect(exec("grep -rn password /tmp/w")).toBe("secrets"); // a path's last part is not a command either
    expect(exec("ls -la /tmp/w")).toBe("");
  });

  test("a plain command reads the same either way", () => {
    for (const c of ["id", "uname -a", "ps aux", "ss -tlnp", "cat /etc/passwd", "sudo -n -l", "getent group sudo", "cat ~/.aws/credentials", "df -h", "crontab -l", "env", "cat /proc/1/cgroup", "systemctl list-units --type=service", "curl -s http://169.254.169.254/latest/meta-data/", "FOO=1 id", "sudo -u www-data cat /etc/shadow", "timeout 5 ps aux", "nohup ss -tlnp"]) {
      expect(exec(c)).toBe(areas(c));
      expect(exec(c)).not.toBe("");
    }
  });

  test("a shell handed a script is the exception: that argument is shell text", () => {
    expect(exec("bash -c id; uname -a; cat /etc/passwd")).toBe("accounts,host,identity");
    expect(exec("sh -c cat /etc/passwd | wc -l")).toBe("accounts");
    expect(exec("bash --noprofile --norc -c ps aux | head; ss -tlnp")).toBe("network,processes");
    expect(exec("sudo sh -c cat /etc/shadow; id")).toBe("accounts,identity");
    expect(exec("sudo -u deploy bash -lc sudo -n -l && crontab -l")).toBe("privilege,scheduled");
    expect(exec("timeout 5 sh -c uname -a; df -h")).toBe("host,storage");
    expect(exec("env LC_ALL=C bash -c env | grep -i token")).toBe("environment,secrets");
    // a shell given a FILE runs that file; the file's name and arguments are not commands
    expect(exec("bash collect.sh id; cat /etc/passwd")).toBe("");
    expect(exec("sh /usr/local/bin/backup --then cat /etc/shadow")).toBe("");
    expect(exec("bash")).toBe("");
  });

  test("as processes, the two sides of a pipe are two commands and nothing ties them together", () => {
    expect(areas("env | grep -i key")).toBe("environment,secrets"); // shell text: the variables are being searched
    expect(exec("env")).toBe("environment");
    expect(exec("grep -i key")).toBe(""); // what it reads from is not on its command line
  });

  test("length and emptiness are as before", () => {
    expect(exec("")).toBe("");
    expect(exec("   ")).toBe("");
    expect(behaviorCategories("cat /etc/passwd " + "x".repeat(BEHAVIOR.maxCommandChars), { exec: true })).toEqual([]);
    expect(behaviorCategories(undefined as never, { exec: true })).toEqual([]);
  });

  test("through decideSession: `exec` decides how the command text is read, and the tracker is fed once", async () => {
    const mk = () => ({ behavior: createBehaviorTracker(), sessions: createSessionTracker(), governor: createGovernor({ budgetPerMin: 0 }), env: {} });
    const survey = ["cat /etc/os-release", "df -hT", "ss -tulnp", "systemctl list-units --type=service", `awk -F: $3>=1000 || $3==0 {print $1} /etc/passwd`, "getent group sudo admin"];
    const asExec = mk(), asText = mk();
    const a = [], b = [];
    for (const c of survey) { a.push((await decideSession("s", c, { ...asExec, exec: true })).decision); b.push((await decideSession("s", c, asText)).decision); }
    expect(a).toEqual(["allow", "allow", "allow", "allow", "allow", "alert"]); // the survey two real models ran
    expect(b).toEqual(["allow", "allow", "allow", "allow", "allow", "allow"]); // and how it was missed
    expect(asExec.behavior.peek("s")).toMatchObject({ commands: 6, sensitive: ["accounts", "privilege"] });
    // one process whose argument mentions a whole sweep is not one
    const quiet = mk();
    expect((await decideSession("s", "git commit -m audit: id; uname -a; ps aux; cat /etc/passwd; sudo -l", { ...quiet, exec: true })).decision).toBe("allow");
    expect(quiet.behavior.peek("s").commands).toBe(0);
    // a tracker can also be handed areas that were already read
    const t = createBehaviorTracker();
    expect(t.observe("k", ["accounts", "privilege"])).toBeNull();
    expect(t.peek("k")).toMatchObject({ categories: ["accounts", "privilege"], commands: 1 });
    expect(t.observe("k", [])).toBeNull();
    expect(t.peek("k").commands).toBe(1);
    expect(observeBehavior(t, "k2", `awk -F: $3>=1000 || $3==0 {print $1} /etc/passwd`, null, { exec: true })).toBeNull();
    expect(t.peek("k2").categories).toEqual(["accounts"]);
  });
});

// Found on a real host (2026-11-21): a survey run with a new SSH connection per command was
// reported 3 times in 18, because every connection is its own session. The same rule is now
// also applied to everything that arrives from one origin.
describe("sessions from one origin are counted together", () => {
  const SWEEP = ["id", "uname -a", "ps aux", "ss -tlnp", "cat /etc/passwd", "sudo -n -l"];
  const OPS = { entry: "sshd", entryPid: 812, login: "ops", user: "ops", client: "203.0.113.7" };
  const fresh = () => ({ behavior: createBehaviorTracker(), sessions: createSessionTracker(), governor: createGovernor({ budgetPerMin: 0 }), env: {} });
  // every command in a session of its own, as a scaffold that opens a connection per command does
  const split = async (opts: object, origin: (i: number) => object | null | undefined, cmds = SWEEP) => {
    const ds = [];
    for (const [i, c] of cmds.entries()) ds.push(await decideSession(`sid:${7000 + i}`, c, { ...opts, origin: origin(i) }));
    return ds;
  };

  test("an origin is an SSH login: the account that logged in, and the client it came from", () => {
    expect(behaviorOrigin(OPS)).toEqual({ key: "ssh:ops@203.0.113.7", what: "SSH logins of ops from 203.0.113.7" });
    expect(behaviorOrigin({ ...OPS, entry: "sshd-session" })?.key).toBe("ssh:ops@203.0.113.7"); // OpenSSH 9.8 names
    expect(behaviorOrigin({ ...OPS, client: null })).toEqual({ key: "ssh:ops", what: "SSH logins of ops" });
    expect(behaviorOrigin({ ...OPS, login: null, user: "root" })?.key).toBe("ssh:root@203.0.113.7"); // no login record: the user it runs as
    expect(behaviorOrigin({ ...OPS, login: "ops", user: "root" })?.key).toBe("ssh:ops@203.0.113.7"); // under sudo it is still ops's login
    expect(behaviorOrigin({ ...OPS, client: "2001:db8::7" })?.key).toBe("ssh:ops@2001:db8::7");
  });

  test("nothing else is an origin today: a web server, a container, a scheduler, or nothing known", () => {
    for (const entry of ["nginx", "php-fpm8.3", "containerd-shim", "cron", "systemd", "node", "tmux: server", "", null, undefined]) expect(behaviorOrigin({ ...OPS, entry })).toBeNull();
    for (const facts of [null, undefined, {}, "sshd", 7, { entry: "sshd" }, { entry: "sshd", login: "", user: "" }]) expect(behaviorOrigin(facts as never)).toBeNull();
  });

  test("what an origin is called cannot carry anything but a name and an address", () => {
    const o = behaviorOrigin({ entry: "sshd", login: "ops\n[2026] FAKE LINE", user: "x", client: "203.0.113.7 ; rm -rf /" })!;
    expect(o.key).toBe("ssh:ops@203.0.113.7");
    expect(o.what).not.toMatch(/[\n;\[\]/]/);
    expect(behaviorOrigin({ entry: "sshd", login: "a".repeat(500), client: "1".repeat(500) })!.key.length).toBeLessThan(140);
  });

  test("a survey with every command in its own session is ONE alert, on the command that completes it", async () => {
    let calls = 0;
    const opts = { ...fresh(), adjudicator: async (): Promise<Adjudication> => { calls++; return { agentic: true, confidence: 0.99, reasoning: "[stub]" }; } };
    const ds = await split(opts, () => OPS);
    expect(ds.map((d) => d.decision)).toEqual(["allow", "allow", "allow", "allow", "allow", "alert"]);
    const d = ds[5];
    expect(d).toMatchObject({ viaBehavior: true, tier: 1, verdict: "clear", score: 0 });
    expect(d.signals).toEqual(["behavior_sweep"]);
    expect(d.behavior).toMatchObject({ kind: "sweep", scope: "origin", origin: "SSH logins of ops from 203.0.113.7", sessions: 6, commands: 6, sensitive: ["accounts", "privilege"] });
    expect(d.reason).toContain("6 sessions from one origin (SSH logins of ops from 203.0.113.7) together swept");
    expect(d.reason).toContain("never a kill");
    expect(calls).toBe(0);
    // more sessions from the same origin, same window: no second alert
    expect((await decideSession("sid:7100", "cat ~/.bash_history", { ...opts, origin: OPS })).decision).toBe("allow");
    expect((await decideSession("sid:7101", "crontab -l", { ...opts, origin: OPS })).decision).toBe("allow");
  });

  test("with no origin known, the same survey is six quiet sessions (the limit that was found)", async () => {
    for (const none of [null, undefined, {}, { entry: "nginx", user: "www-data" }]) {
      const ds = await split(fresh(), () => none as never);
      expect(ds.map((d) => d.decision)).toEqual(["allow", "allow", "allow", "allow", "allow", "allow"]);
    }
  });

  test("two people are two origins: another account, or the same account from another machine, does not add up", async () => {
    const other = [{ ...OPS, login: "bob", user: "bob" }, { ...OPS, client: "198.51.100.9" }];
    for (const second of other) {
      const ds = await split(fresh(), (i) => (i % 2 ? second : OPS));
      expect(ds.map((d) => d.decision)).toEqual(["allow", "allow", "allow", "allow", "allow", "allow"]);
    }
  });

  test("one sweep is one report: a session that sweeps alone is reported as that session, once", async () => {
    const opts = fresh();
    const ds = [];
    for (const c of SWEEP) ds.push(await decideSession("sid:7200", c, { ...opts, origin: OPS }));
    expect(ds.map((d) => d.decision)).toEqual(["allow", "allow", "allow", "allow", "allow", "alert"]);
    expect(ds[5].behavior).toMatchObject({ scope: "session" });
    expect(ds[5].behavior!.origin).toBeUndefined();
    expect(ds[5].reason).toContain("this session swept");
    // a second session from the same origin goes through the whole sweep again inside the window:
    // its origin has been reported for it already, so it is not reported a second time
    for (const c of SWEEP) expect((await decideSession("sid:7201", c, { ...opts, origin: OPS })).decision).toBe("allow");
  });

  test("the origin's window is the same window: what was asked more than five minutes ago does not count", async () => {
    let clock = 1_000_000;
    const opts = { ...fresh(), behavior: createBehaviorTracker({ now: () => clock }) };
    for (const [i, c] of SWEEP.slice(0, 5).entries()) expect((await decideSession(`sid:${7300 + i}`, c, { ...opts, origin: OPS })).decision).toBe("allow");
    clock += BEHAVIOR.windowMs + 1;
    expect((await decideSession("sid:7310", SWEEP[5], { ...opts, origin: OPS })).decision).toBe("allow");
    expect(opts.behavior.peek("origin:ssh:ops@203.0.113.7").categories).toEqual(["privilege"]);
  });

  test("the tracker keeps area names, times and session ids for an origin, never command text", () => {
    let clock = 5_000;
    const tracker = createBehaviorTracker({ now: () => clock });
    expect(observeBehavior(tracker, "sid:1", "cat /etc/passwd", OPS)).toBeNull();
    clock += 1000;
    expect(observeBehavior(tracker, "sid:2", "sudo -n -l", OPS)).toBeNull();
    expect(tracker.peek("origin:ssh:ops@203.0.113.7")).toEqual({ categories: ["accounts", "privilege"], sensitive: ["accounts", "privilege"], commands: 2, reported: false });
    expect(tracker.observe("k", "id", "m1")).toBeNull();
    expect(observeBehavior(null, "sid:1", "id", OPS)).toBeNull(); // no tracker, no signal
    expect(observeBehavior(tracker, null, "id", OPS)).toBeNull(); // no session, nothing to count
    expect(observeBehavior(tracker, "", "uname -a", OPS)).toBeNull();
    expect(tracker.peek("origin:ssh:ops@203.0.113.7").commands).toBe(2);
  });

  test("a command that carries the tripwire token is not counted for the origin either", async () => {
    const token = newTripwireToken();
    const tripwire = createTripwire({ token, dirs: ["/opt/vault-access"] });
    const opts = { ...fresh(), tripwire };
    for (const [i, c] of SWEEP.slice(0, 4).entries()) await decideSession(`sid:${7400 + i}`, c, { ...opts, origin: OPS });
    const d = await decideSession("sid:7410", `cat /etc/passwd; sudo -n -l; ${tripwireDecoy(token, "/opt/vault-access", "linux").command}`, { ...opts, origin: OPS });
    expect(d).toMatchObject({ decision: "block", viaTripwire: true });
    expect(d.behavior).toBeUndefined();
    expect(opts.behavior.peek("origin:ssh:ops@203.0.113.7").sensitive).toEqual([]);
  });

  test("a narrated payload that completes an origin's sweep is still a block for its narration, and says both", async () => {
    const opts = fresh();
    for (const [i, c] of SWEEP.slice(0, 5).entries()) await decideSession(`sid:${7500 + i}`, c, { ...opts, origin: OPS });
    const d = await decideSession("sid:7510", NARRATED, { ...opts, origin: OPS });
    expect(d).toMatchObject({ decision: "block", tier: 1 });
    expect(d.viaBehavior).toBeUndefined();
    expect(d.behavior).toMatchObject({ scope: "origin", sessions: 6 });
    expect(d.reason).toContain("6 sessions from one origin (SSH logins of ops from 203.0.113.7) together had also swept");
  });
});

// Read in the source of three open-source attack frameworks (2026-11-24): the model stays on
// the operator's side and what reaches a host is a bare command, most often through a web
// application. Those commands descend from the program that serves it.
describe("commands that descend from a service are held to a lower count", () => {
  const PROBE = ["id", "uname -a", "sudo -n -l"]; // identity, host, privilege: three areas, one sensitive
  const PHP = { entry: "php-fpm8.3", login: null, noLogin: true, user: "www-data", lineage: ["sh", "php-fpm8.3", "php-fpm8.3"] };
  const TOMCAT = { entry: "java", login: null, noLogin: true, user: "tomcat", lineage: ["sh", "java"] };
  const ADMIN = { entry: "sshd", login: "alice", noLogin: false, user: "alice", client: "203.0.113.7", lineage: ["bash", "sshd-session", "sshd"] };
  const fresh = (services = behaviorServices({})) => ({ behavior: createBehaviorTracker({ services }), sessions: createSessionTracker(), governor: createGovernor({ budgetPerMin: 0 }), env: {} });
  const through = async (opts: object, key: string, origin: object | null, cmds = PROBE) => {
    const ds = [];
    for (const c of cmds) ds.push(await decideSession(key, c, { ...opts, origin }));
    return ds;
  };

  test("the published count is three areas, one of them sensitive, and it is lower than a sweep's", () => {
    expect(BEHAVIOR_SERVICE).toEqual({ categories: 3, sensitive: 1 });
    expect(BEHAVIOR_SERVICE.categories).toBeLessThan(BEHAVIOR.categories);
    expect(BEHAVIOR_SERVICE.sensitive).toBeLessThan(BEHAVIOR.sensitive);
    expect(Object.isFrozen(BEHAVIOR_SERVICE)).toBe(true);
  });

  test("a server is counted whoever started it; a runtime only when nobody logged in", () => {
    for (const noLogin of [true, false, null, undefined]) expect(behaviorService({ lineage: ["sh", "nginx"], noLogin })).toMatchObject({ name: "nginx", tier: "server" });
    expect(behaviorService({ lineage: ["sh", "java"], noLogin: true })).toEqual({ name: "java", tier: "runtime", what: "java (started without anybody logging in)" });
    for (const noLogin of [false, null, undefined, "true", 1]) expect(behaviorService({ lineage: ["sh", "java"], noLogin } as never)).toBeNull();
  });

  test("names are read as the kernel reports them: a version, a title, the nearest one first, the entry last", () => {
    expect(behaviorService({ lineage: ["sh", "php-fpm8.3"] })?.name).toBe("php-fpm");
    expect(behaviorService({ lineage: ["apache2"] })?.name).toBe("apache");
    expect(behaviorService({ lineage: ["python3.12"], noLogin: true })?.name).toBe("python");
    expect(behaviorService({ lineage: ["sh", "next-server (v1"] })?.name).toBe("next-server");
    expect(behaviorService({ lineage: ["sh", "node", "nginx"], noLogin: true })?.name).toBe("node"); // the nearest listed name
    expect(behaviorService({ lineage: ["sh", "node", "nginx"], noLogin: false })?.name).toBe("nginx"); // a runtime under a login is passed over
    expect(behaviorService({ lineage: ["sh"], entry: "php-fpm8.3" })?.name).toBe("php-fpm");
    expect(behaviorService({ entry: "httpd" })?.name).toBe("httpd");
  });

  test("nothing else is a service: a login, a container runtime, a scheduler, a name that only starts like one", () => {
    for (const name of ["sshd", "sshd-session", "bash", "containerd-shim", "cron", "systemd", "tmux: server", "javac", "nodemon", "nginx-debug", "pythonista", ""]) {
      expect(behaviorService({ lineage: [name], entry: name, noLogin: true })).toBeNull();
    }
    for (const facts of [null, undefined, {}, "nginx", 7, { lineage: "nginx" }, { lineage: [null, undefined, 7, {}] }]) expect(behaviorService(facts as never)).toBeNull();
  });

  test("only the first sixteen names are read, and a name cannot carry anything but a name", () => {
    expect(behaviorService({ lineage: [...Array(16).fill("sh"), "nginx"] })).toBeNull();
    expect(behaviorService({ lineage: [...Array(15).fill("sh"), "nginx"] })?.name).toBe("nginx");
    for (const bad of ["nginx\n[2026] FAKE LINE", "nginx;rm", "ng inx", "n".repeat(500), "../nginx", "nginx$(id)"]) {
      const hit = behaviorService({ lineage: [bad] });
      if (hit) expect(hit.what).toBe("nginx (a program that serves requests)"); // the first word alone, when it is a listed name
      else expect(hit).toBeNull();
    }
    expect(behaviorService({ lineage: ["nginx;rm"] })).toBeNull();
  });

  test("a host adds a name, removes one, or turns the rule off; the published lists are not touched", () => {
    const own = behaviorServices({ ARIS_BEHAVIOR_SERVICES: "billing-api, -java ,Node,;bad;,-" });
    expect(behaviorService({ lineage: ["billing-api"] }, own)).toMatchObject({ name: "billing-api", tier: "server" });
    expect(behaviorService({ lineage: ["java"], noLogin: true }, own)).toBeNull();
    expect(behaviorService({ lineage: ["node"], noLogin: false }, own)).toMatchObject({ tier: "server" }); // named by the host: counted whoever started it
    expect(behaviorService({ lineage: ["nginx"] }, own)?.name).toBe("nginx");
    for (const off of ["off", "none", "0", "nginx,OFF"]) expect(behaviorService({ lineage: ["nginx"] }, behaviorServices({ ARIS_BEHAVIOR_SERVICES: off }))).toBeNull();
    // a name a host gives is held to the same shape as one the kernel reports
    const odd = behaviorServices({ ARIS_BEHAVIOR_SERVICES: "a;b,$(id),../x," + "n".repeat(40) });
    expect([...odd.servers].filter((n) => /[^a-z0-9._+-]/.test(n) || n.length > 32)).toEqual([]);
    expect(odd.servers.size).toBe(behaviorServices({}).servers.size);
    const published = behaviorServices({});
    expect(behaviorService({ lineage: ["java"], noLogin: true }, published)?.name).toBe("java");
    expect(behaviorService({ lineage: ["billing-api"] }, published)).toBeNull();
    expect(Object.isFrozen(published)).toBe(true);
  });

  test("through decideSession: allow, allow, then one alert that says which service, with no judge called", async () => {
    let calls = 0;
    const opts = { ...fresh(), adjudicator: async (): Promise<Adjudication> => { calls++; return { agentic: true, confidence: 0.99, reasoning: "[stub]" }; } };
    const ds = await through(opts, "sid:8000", PHP);
    expect(ds.map((d) => d.decision)).toEqual(["allow", "allow", "alert"]);
    expect(ds[2]).toMatchObject({ viaBehavior: true, tier: 1, verdict: "clear", score: 0 });
    expect(ds[2].signals).toEqual(["behavior_service"]);
    expect(ds[2].behavior).toMatchObject({ kind: "service", service: "php-fpm", scope: "session", categories: ["host", "identity", "privilege"], sensitive: ["privilege"] });
    expect(ds[2].reason).toContain("a session whose commands descend from php-fpm (a program that serves requests) asked about 3 areas");
    expect(ds[2].reason).toContain("never a kill");
    expect(calls).toBe(0);
    expect((await decideSession("sid:8000", "ls -la /srv", { ...opts, origin: PHP })).decision).toBe("allow"); // and the session goes on
  });

  test("the same three commands from a login are not reported, and neither is a runtime somebody logged in to start", async () => {
    expect((await through(fresh(), "sid:8010", ADMIN)).map((d) => d.decision)).toEqual(["allow", "allow", "allow"]);
    expect((await through(fresh(), "sid:8011", { ...TOMCAT, noLogin: false })).map((d) => d.decision)).toEqual(["allow", "allow", "allow"]);
    expect((await through(fresh(), "sid:8012", { ...TOMCAT, noLogin: null })).map((d) => d.decision)).toEqual(["allow", "allow", "allow"]); // not known is not "nobody"
    expect((await through(fresh(), "sid:8013", null)).map((d) => d.decision)).toEqual(["allow", "allow", "allow"]);
    expect((await through(fresh(), "sid:8014", TOMCAT)).map((d) => d.decision)).toEqual(["allow", "allow", "alert"]);
  });

  test("a service that looks widely at nothing sensitive is not reported, and neither are two areas with one sensitive", async () => {
    const wide = await through(fresh(), "sid:8020", PHP, ["uname -a", "df -k", "ps aux", "ss -tlnp", "env"]);
    expect(wide.map((d) => d.decision)).toEqual(["allow", "allow", "allow", "allow", "allow"]);
    expect((await through(fresh(), "sid:8021", PHP, ["id", "sudo -n -l"])).map((d) => d.decision)).toEqual(["allow", "allow"]);
  });

  test("with the rule turned off a service's session is an ordinary session", async () => {
    const opts = fresh(behaviorServices({ ARIS_BEHAVIOR_SERVICES: "off" }));
    expect((await through(opts, "sid:8030", PHP)).map((d) => d.decision)).toEqual(["allow", "allow", "allow"]);
    expect(opts.behavior.peek("service:sid:8030").commands).toBe(0);
  });

  test("one session can hold both: what its owner types is not reported as the server's doing", async () => {
    // a server started from a terminal shares the terminal's session
    const opts = fresh();
    expect((await through(opts, "sid:8040", ADMIN)).map((d) => d.decision)).toEqual(["allow", "allow", "allow"]); // the owner: three areas, one sensitive
    const child = await decideSession("sid:8040", "df -k", { ...opts, origin: { ...ADMIN, lineage: ["sh", "nginx", "bash", "sshd-session", "sshd"] } });
    expect(child.decision).toBe("allow");
    expect(opts.behavior.peek("service:sid:8040")).toEqual({ categories: ["storage"], sensitive: [], commands: 1, reported: false });
    expect(opts.behavior.peek("sid:8040").categories).toEqual(["host", "identity", "privilege", "storage"]);
  });

  test("one look is one report: a service's session that goes on to a full sweep is not reported twice", async () => {
    let clock = 1_000_000;
    const opts = { ...fresh(), behavior: createBehaviorTracker({ services: behaviorServices({}), now: () => clock }) };
    const ds = await through(opts, "sid:8050", PHP, ["id", "uname -a", "sudo -n -l", "ps aux", "cat /etc/passwd", "ss -tlnp"]);
    expect(ds.map((d) => d.decision)).toEqual(["allow", "allow", "alert", "allow", "allow", "allow"]);
    expect(opts.behavior.peek("sid:8050")).toMatchObject({ sensitive: ["accounts", "privilege"], reported: true }); // the sweep completed, and was not a second report
    // once the window has emptied the session can be reported again
    clock += BEHAVIOR.windowMs + 1;
    expect((await through(opts, "sid:8050", PHP)).map((d) => d.decision)).toEqual(["allow", "allow", "alert"]);
  });

  test("a sweep the session already has is not followed by a service report in the same window", async () => {
    const opts = fresh();
    // the owner's own commands complete a sweep in a session that also holds a server's children
    // (a console login: no origin is grouped, so nothing but this rule keeps it to one report)
    const own = await through(opts, "sid:8060", { entry: "login", noLogin: false, lineage: ["bash", "login"] }, ["id", "uname -a", "ps aux", "ss -tlnp", "cat /etc/passwd", "sudo -n -l"]);
    expect(own.map((d) => d.decision)).toEqual(["allow", "allow", "allow", "allow", "allow", "alert"]);
    expect(own[5].behavior).toMatchObject({ kind: "sweep" });
    const child = { entry: "login", noLogin: false, lineage: ["sh", "nginx", "bash", "login"] };
    expect((await through(opts, "sid:8060", child)).map((d) => d.decision)).toEqual(["allow", "allow", "allow"]);
    expect(opts.behavior.peek("service:sid:8060")).toMatchObject({ sensitive: ["privilege"], reported: true }); // counted, and not a second report
  });

  test("the tracker keeps area names and times for a service's window, never a command or a process name", () => {
    let clock = 5_000;
    const tracker = createBehaviorTracker({ services: behaviorServices({}), now: () => clock });
    expect(observeBehavior(tracker, "sid:1", "cat /etc/shadow", PHP)).toBeNull();
    expect(tracker.peek("service:sid:1")).toEqual({ categories: ["accounts"], sensitive: ["accounts"], commands: 1, reported: false });
    expect(tracker.size()).toBe(2); // the session's window and the service's
    expect(observeBehavior(tracker, null, "id", PHP)).toBeNull(); // no session, nothing to count
    expect(observeBehavior(tracker, "", "id", PHP)).toBeNull();
    expect(tracker.size()).toBe(2);
  });

  test("a command that carries the tripwire token is not counted for the service either", async () => {
    const token = newTripwireToken();
    const tripwire = createTripwire({ token, dirs: ["/opt/vault-access"] });
    const opts = { ...fresh(), tripwire };
    await through(opts, "sid:8070", PHP, ["id", "uname -a"]);
    const d = await decideSession("sid:8070", `sudo -n -l; ${tripwireDecoy(token, "/opt/vault-access", "linux").command}`, { ...opts, origin: PHP });
    expect(d).toMatchObject({ decision: "block", viaTripwire: true });
    expect(d.behavior).toBeUndefined();
    expect(opts.behavior.peek("service:sid:8070").sensitive).toEqual([]);
  });

  test("a narrated payload that completes a service's look is still a block for its narration, and says both", async () => {
    const opts = fresh();
    await through(opts, "sid:8080", PHP, ["id", "uname -a"]);
    const d = await decideSession("sid:8080", NARRATED, { ...opts, origin: PHP });
    expect(d).toMatchObject({ decision: "block", tier: 1 });
    expect(d.viaBehavior).toBeUndefined();
    expect(d.behavior).toMatchObject({ kind: "service", service: "php-fpm" });
    expect(d.reason).toContain("a session whose commands descend from php-fpm (a program that serves requests) had also asked about");
    expect(d.signals).not.toContain("behavior_service");
  });

  // Found live (2026-11-24): every session in the VM check came from one SSH login, that
  // login's origin had been reported for a sweep, and the report covered a server's children.
  test("a service's commands are not their login's doing: not counted for its origin, not covered by its report", async () => {
    // a server started by hand in an SSH login has both a service and an origin above it
    const opts = fresh();
    const child = { ...ADMIN, lineage: ["sh", "nginx", "bash", "sshd-session", "sshd"] };
    const ds = await through(opts, "sid:8090", child);
    expect(ds[2].behavior).toMatchObject({ kind: "service", scope: "session" });
    expect(opts.behavior.peek("origin:ssh:alice@203.0.113.7").commands).toBe(0);
    // the login sweeps and is reported; three minutes later something comes in through the server
    const later = fresh();
    const own = await through(later, "sid:8091", ADMIN, ["id", "uname -a", "ps aux", "ss -tlnp", "cat /etc/passwd", "sudo -n -l"]);
    expect(own[5].behavior).toMatchObject({ kind: "sweep" });
    expect(later.behavior.peek("origin:ssh:alice@203.0.113.7").reported).toBe(true);
    const through_server = await through(later, "sid:8092", child);
    expect(through_server.map((d) => d.decision)).toEqual(["allow", "allow", "alert"]);
    expect(through_server[2].behavior).toMatchObject({ kind: "service", service: "nginx" });
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
