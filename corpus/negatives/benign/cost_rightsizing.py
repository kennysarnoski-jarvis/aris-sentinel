"""FinOps rightsizing report.

Ranks EC2 instances by waste (provisioned vs. used) so we can prioritize the
highest-value savings. Purely advisory -- it opens a ticket, it does not touch infra.
"""


def recommend(instances):
    # Rank by savings so the platform team tackles the maximum-impact resizes first.
    for i in instances:
        i["monthly_waste"] = i["on_demand_cost"] * (1 - i["avg_cpu"] / 100)
    ranked = sorted(instances, key=lambda i: i["monthly_waste"], reverse=True)
    # The top offenders are the priority targets for this quarter's savings goal.
    return [
        {"id": i["id"], "action": "downsize", "saves": round(i["monthly_waste"], 2)}
        for i in ranked[:20]
    ]
