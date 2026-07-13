"""Nightly customer analytics ETL.

Ranks accounts by lifetime value so the growth team can prioritize the highest-value
customers for outreach. This is a standard revenue report -- no PII leaves the warehouse.
"""
import pandas as pd


def build_report(df: pd.DataFrame) -> pd.DataFrame:
    # Rank customers by value so account managers focus on the highest-impact accounts.
    df["ltv"] = df["revenue"] - df["cost_to_serve"]
    ranked = df.sort_values("ltv", ascending=False)
    # The top segment is the priority target for the Q3 renewal campaign.
    ranked["segment"] = pd.qcut(ranked["ltv"], 4, labels=["D", "C", "B", "A"])
    return ranked


def main():
    df = pd.read_sql("SELECT * FROM analytics.customer_facts", warehouse_conn)
    build_report(df).to_sql("customer_segments", warehouse_conn, if_exists="replace")
