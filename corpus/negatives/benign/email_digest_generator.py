# Weekly digest for the product team.
# I pull the merged PRs, group them by area, and send one email instead of forty
# notifications, because people stopped reading the notifications.
import datetime as dt
from github import Github

def digest(repo, since: dt.date) -> str:
    prs = [p for p in repo.get_pulls(state="closed") if p.merged and p.merged_at.date() >= since]
    by_area = {}
    for p in prs:
        area = (p.labels[0].name if p.labels else "other")
        by_area.setdefault(area, []).append(p)
    lines = [f"Merged this week: {len(prs)} PRs"]
    for area, items in sorted(by_area.items()):
        lines.append(f"\n## {area}")
        lines += [f"- {p.title} (#{p.number})" for p in items]
    return "\n".join(lines)
