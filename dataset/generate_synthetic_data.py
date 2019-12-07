import pandas as pd
import random

data = []
count = {}
for i in range(10):
    for j in range(2**(10-i)):
        ts = random.randint(1, 100)
        data.append([i+1, ts, 2**(10-i)])
        count[i+1, ts] = count.get((i+1, ts), 0) + 1

for i in range(len(data)):
    dport = data[i][0]
    ts = data[i][1]
    data[i].append(count.get((dport, ts)))

df_top = pd.DataFrame(data, columns=["dport", "ts", "total count", "count"])
df_top = df_top.drop_duplicates()
df_top.to_csv("Synthetic_top10.csv", index=None)

i = 10
while len(data) < 10000:
    ts = random.randint(1, 100)
    data.append([i+1, ts, 1, 1])
    i += 1

df = pd.DataFrame(data, columns=["dport", "ts", "total count", "count"])
df.to_csv("Synthetic.csv", index=None)
