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

f=f"{BASE}/handover_runway_sweep_aggregate_summary.csv"

df=pd.read_csv(f)

report.append("\nTable VII: Handover Ablation (DR vs. post-crossing runway tau)")

expected_on={
1.0:94.7,
1.1:94.7,
1.2:94.7,
1.3:94.7,
1.4:94.7,
1.5:97.3
}

expected_off={
1.0:0.0,
1.1:24.0,
1.2:32.0,
1.3:48.0,
1.4:69.3,
1.5:97.3
}

for tau,v in expected_on.items():

    row=df[(df.condition=="ON") & (df.tau_sec==tau)].iloc[0]

    check(
        f"Handover ON tau={tau}s DR {v}",
        round(float(row.pooled_DR_percent),2)==v
    )

for tau,v in expected_off.items():

    row=df[(df.condition=="OFF") & (df.tau_sec==tau)].iloc[0]

    check(
        f"Handover OFF tau={tau}s DR {v}",
        round(float(row.pooled_DR_percent),2)==v
    )

check(
"Handover FPR 0.00 for all tau, both conditions",
bool((df.pooled_FPR_percent==0.0).all())
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
