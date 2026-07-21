import pandas as pd
import os

BASE="results/final_locked_csv"

report=[]

def check(title, condition):
    if condition:
        report.append(f"{title}: PASS ✓")
    else:
        report.append(f"{title}: FAIL ✗")


report.append("="*60)
report.append("V2X MULTI-UAV TRUST ARTIFACT VERIFICATION")
report.append("="*60)


# ------------------------------------------------
# Table VII Handover
# ------------------------------------------------

f=f"{BASE}/handover_onoff_aggregate_summary.csv"

df=pd.read_csv(f)

on=df[df.condition=="ON"].iloc[0]
off=df[df.condition=="OFF"].iloc[0]

report.append("\nTable VII: Handover Ablation")

check(
"Handover ON DR 96.19",
round(on.pooled_DR_percent,2)==96.19
)

check(
"Handover OFF DR 41.90",
round(off.pooled_DR_percent,2)==41.90
)


# ------------------------------------------------
# Table IX CUSUM
# ------------------------------------------------

f=f"{BASE}/guarded_cusum_onoff_aggregate_summary.csv"

df=pd.read_csv(f)

report.append("\nTable IX: Guarded CUSUM Ablation")

on=df[df.condition=="ON"].iloc[0]
off=df[df.condition=="OFF"].iloc[0]


check(
"CUSUM ON DR 96.19",
round(on.pooled_DR_percent,2)==96.19
)

check(
"CUSUM OFF DR 71.43",
round(off.pooled_DR_percent,2)==71.43
)



# ------------------------------------------------
# Table XI Attack Robustness
# ------------------------------------------------

report.append("\nTable XI: Beacon Falsification Probability")

f=f"{BASE}/attack_rate_robustness_aggregate_summary.csv"

df=pd.read_csv(f)


expected={
"AR20_N10":95.56,
"AR50_N10":96.19,
"AR70_N10":96.30
}


for k,v in expected.items():

    value=float(
        df[df.condition==k]
        .pooled_DR_percent
        .iloc[0]
    )

    check(
        f"{k} DR {v}",
        round(value,2)==v
    )


# AR80 extended

f=f"{BASE}/attack_rate_robustness_extended_aggregate_summary.csv"

df=pd.read_csv(f)

value=float(
df[df.condition=="AR80_N10"]
.pooled_DR_percent
.iloc[0]
)

check(
"AR80_N10 DR 96.67",
round(value,2)==96.67
)



# ------------------------------------------------
# Table XIV Scalability
# ------------------------------------------------

report.append("\nTable XIV: Scalability")

f=f"{BASE}/scalability_aggregate_summary.csv"

df=pd.read_csv(f)

expected={
10:96.19,
20:83.08,
30:72.28,
50:52.29
}


for n,v in expected.items():

    value=float(
        df[df.nCars==n]
        .pooled_DR_percent
        .iloc[0]
    )

    check(
        f"N={n} DR {v}",
        round(value,2)==v
    )



report.append("\n"+"="*60)
report.append("VERIFICATION COMPLETED")
report.append("="*60)



with open(
"artifact_verification_report.txt",
"w"
) as f:

    f.write("\n".join(report))


print("\n".join(report))
