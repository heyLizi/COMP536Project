import pandas as pd
from datetime import datetime
from pickle_query import load_query

def process(query_2_dport, topk, drop_duplicate=False):
    df_origin = pd.read_table("AOL_origin.txt", sep='\t')

    date_2_timestamp = lambda x: datetime.timestamp(datetime.strptime(x, "%Y-%m-%d %H:%M:%S"))

    min_timestamp = df_origin["QueryTime"].apply(date_2_timestamp).min()

    df_origin["QueryTime"] = df_origin["QueryTime"].apply(lambda x: (date_2_timestamp(x) - min_timestamp) // 3600 + 1)

    df_top = df_origin.iloc[:, 1:3]
    df_top["ts"] = df_top["QueryTime"].apply(int)
    del df_top["QueryTime"]

    top_ts = set(range(1, 101))
    df_top = df_top.loc[df_top["ts"].isin(top_ts)]

    top_querys = set(df_top["Query"].value_counts()[:topk].to_dict().keys())

    df_top = df_top.loc[df_top["Query"].isin(top_querys)]
    df_top["dport"] = df_top["Query"].apply(lambda x: query_2_dport.get(x))

    count = {}
    for i in range(len(df_top)):
        row = df_top.iloc[i]
        dport = row["dport"]
        ts = row["ts"]
        count[dport, ts] = count.get((dport, ts), 0) + 1
    
    df_top["count"] = df_top.apply(lambda row: count[row["dport"], row["ts"]], axis=1)

    if drop_duplicate:
        df_top = df_top.drop_duplicates()

    df_top.to_csv("AOL_100t_top%d.csv" % topk, index=None)


if __name__ == '__main__':
    query_2_dport = load_query()
    process(query_2_dport, 100)
    process(query_2_dport, 10, True)