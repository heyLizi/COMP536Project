import pandas as pd
from datetime import datetime

df_origin = pd.read_table("AOL_origin.txt", sep='\t')

date_2_timestamp = lambda x: datetime.timestamp(datetime.strptime(x, "%Y-%m-%d %H:%M:%S"))

min_timestamp = df_origin["QueryTime"].apply(date_2_timestamp).min()

df_origin["QueryTime"] = df_origin["QueryTime"].apply(lambda x: (date_2_timestamp(x) - min_timestamp) // 3600 + 1)

df_processed = df_origin.iloc[:, 1:3]
df_processed["QueryTime"] = df_processed["QueryTime"].apply(int)
df_processed["Query"] = df_processed["Query"] + df_processed["QueryTime"].apply(str)
df_processed.to_csv("AOL_processed.csv", index=None)

df_top = df_origin.iloc[:, 1:3]
top_querys = set(df_top["Query"].value_counts()[:1000].to_dict().keys())

df_top1000 = df_top.loc[df_top["Query"].isin(top_querys)]
df_top1000["QueryTime"] = df_top1000["QueryTime"].apply(int)
df_top1000["Query"] = df_top1000["Query"] + df_top1000["QueryTime"].apply(str)

df_top1000.to_csv("AOL_top1000.csv", index=None)

