# VHS tape for the README demo: `vhs docs/demo-score.tape` from the repo root.
# https://github.com/charmbracelet/vhs  (brew install vhs)
# Keep typed text ASCII: multibyte characters confuse the recorded cursor.
Output docs/demo-score.gif

Set Shell "bash"
Set FontSize 14
Set Width 1320
Set Height 720
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 18ms

Hide
Type "clear"
Enter
Type `printf 'exec(__import__("base64").b64decode("%s"))\n' "$(base64 < corpus/positives/agentic_s3_exfil.py | tr -d '\n')" > /tmp/payload.py`
Enter
Type "clear"
Enter
Show

Type "# an agent's attack step vs a human's one-liner, same detector"
Enter
Sleep 600ms
Type "node agent/score.mjs corpus/positives/jadepuffer_retry_fk_bypass.py corpus/negatives/human-malware/reverse_shell.sh"
Sleep 300ms
Enter
Sleep 6s

Type "clear"
Enter
Type "# the same narration, base64-wrapped inside an exec(): the decode stage finds it anyway"
Enter
Sleep 600ms
Type "cut -c1-100 /tmp/payload.py"
Enter
Sleep 1500ms
Type "node agent/score.mjs /tmp/payload.py"
Sleep 300ms
Enter
Sleep 7s
