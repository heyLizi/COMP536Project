import pandas as pd
from datetime import datetime

df_origin = pd.read_table("AOL_origin.txt", sep='\t')

date_2_timestamp = lambda x: datetime.timestamp(datetime.strptime(x, "%Y-%m-%d %H:%M:%S"))

min_timestamp = df_origin["QueryTime"].apply(date_2_timestamp).min()

df_origin["QueryTime"] = df_origin["QueryTime"].apply(lambda x: (date_2_timestamp(x) - min_timestamp) // 3600 + 1)

df_top = df_origin.iloc[:, 1:3]
top_querys = set(df_top["Query"].value_counts()[:10].to_dict().keys())

df_top10 = df_top.loc[df_top["Query"].isin(top_querys)]
df_top10["QueryTime"] = df_top10["QueryTime"].apply(int)
df_top10["QueryT"] = df_top10["Query"] + df_top10["QueryTime"].apply(str)

data = {}
for i in range(len(df_top10)):
    row = df_top10.iloc[i]
    data[row["QueryT"]] = data.get(row["QueryT"], 0) + 1

data2 = []
for i in range(len(df_top10)):
    row = df_top10.iloc[i]
    data2.append([row["Query"], row["QueryT"], row["QueryTime"], data.get(row["QueryT"])])

ans = pd.DataFrame(data2, columns=["Query", "QueryT", "QueryTime", "Count"])
ans = ans.drop_duplicates()

ans.to_csv("AOL_top10_count.csv", index=None)

