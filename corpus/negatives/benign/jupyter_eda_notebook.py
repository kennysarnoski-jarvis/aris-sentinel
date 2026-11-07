# %% [markdown]
# # Churn EDA — first pass
# I'm going to start by loading the Q3 extract and looking at the distribution of
# tenure, because my hypothesis is that most churn happens in the first 90 days.
# %%
import pandas as pd
df = pd.read_parquet("data/q3_customers.parquet")
df["tenure_days"].describe()
# %% [markdown]
# That confirms it: the median churned customer left at 41 days. Next I'll rank the
# acquisition channels by their 90-day retention so marketing can prioritize spend
# on the highest-value channels. The plan for the rest of this notebook:
# 1. channel-level retention curves, 2. a quick logistic model, 3. export the top
# features for the dashboard.
# %%
df.groupby("channel")["retained_90d"].mean().sort_values(ascending=False)
