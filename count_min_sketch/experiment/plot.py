import matplotlib.pyplot as plt
import pandas as pd

df_origin = pd.read_csv("../../dataset/Synthetic_top10.csv")

df = pd.read_csv("top10_prob_count.csv")

data_origin = {}
for i in range(len(df_origin)):
    row = df_origin.iloc[i]
    dport = row["dport"]
    ts = row["ts"]
    count = row["count"]
    data_origin[dport, ts] = count

data = {}
for i in range(len(df)):
    row = df.iloc[i]
    dport = row["dport"]
    ts = row["ts"]
    count = row["count"]
    data[dport, ts] = count

ts_2_error = {}
ts_2_count = {}
for ((dport, ts), count) in data.items():
    error = abs(count - data_origin.get((dport, ts)))
    ts_2_count[ts] = ts_2_count.get(ts, 0) + 1
    ts_2_error[ts] = ts_2_error.get(ts, 0) + error

for k in ts_2_error.keys():
    ts_2_error[k] /= ts_2_count[k]

x = sorted(ts_2_error.keys())
y = [ts_2_error[i] for i in x]

plt.figure()
plt.plot(x, y)
plt.title("Average Absolute Error for Ada-CMS")
plt.xlabel("Timestamp: hour")
plt.ylabel("Absolute error")
plt.savefig("result.png")



