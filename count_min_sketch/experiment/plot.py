import matplotlib.pyplot as plt
import pandas as pd



def process(df, df_origin):
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

    return (x, y)

if __name__ == "__main__":
    # load original count for top10 frequent query
    df_origin = pd.read_csv("../../dataset/AOL_100t_top10.csv")
    df_origin = df_origin.drop_duplicates()

    # read ada-cms prob result file
    df_adcms = pd.read_csv("top10_prob_count_adcms.csv")

    # read cms prob result file
    df_cms = pd.read_csv("top10_prob_count_cms.csv")

    # plot graph
    x_adcms, y_adcms = process(df_adcms, df_origin)
    x_cms, y_cms = process(df_cms, df_origin)

    ax = plt.subplot()
    ax.plot(x_adcms, y_adcms, label='ada-cms')
    ax.plot(x_cms, y_cms, label='cms')

    ax.set_yscale("log", basex=2)
    ax.legend()
    ax.grid()

    plt.title("Average Absolute Error for Ada-CMS")
    plt.xlabel("Timestamp: hour")
    plt.ylabel("Absolute error")
    plt.savefig("result.png")



