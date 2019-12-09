import pickle as pkl
import pandas as pd
from datetime import datetime

def pickle_query():
    data = {}
    df = pd.read_table("AOL_origin.txt", sep='\t')
    date_2_timestamp = lambda x: datetime.timestamp(datetime.strptime(x, "%Y-%m-%d %H:%M:%S"))
    min_timestamp = df["QueryTime"].apply(date_2_timestamp).min()

    df["QueryTime"] = df["QueryTime"].apply(lambda x: (date_2_timestamp(x) - min_timestamp) // 3600 + 1)

    df["ts"] = df["QueryTime"].apply(int)
    del df["QueryTime"]

    top_ts = set(range(1, 101))
    df = df.loc[df["ts"].isin(top_ts)]
    df = df.iloc[:, 1:3]
    querys = set(df["Query"].value_counts()[:1000].to_dict().keys())

    dport = 1
    for query in querys:
        data[query] = dport
        dport += 1

    with open("query_2_dport.pkl", "wb") as f:
        pkl.dump(data, f)

def load_query():
    with open("query_2_dport.pkl", "rb") as f:
        data = pkl.load(f)

    return data

if __name__ == "__main__":
    pickle_query()
    data = load_query()
    print(data)

