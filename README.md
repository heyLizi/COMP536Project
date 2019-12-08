# COMP536Project
## using P4 to do time-adaptive count min sketch  

probe_hdr: used to probe current heavy hitter  

h1: IP: 10.0.1.1	MAC: 00:00:00:01:01  
h2: IP: 10.0.1.2	MAC: 00:00:00:01:02  

st_py: structure test python files  
probe_py: probe python files  

## test  
under count_min_sketch folder  

TIME_ADAPTIVE = 1  // use time adaptive CMS  
TIME_ADAPTIVE = 0  // not use time adaptive CMS  

1. structure test:  
make  
xterm h1 h2  
in h2: ./st_py/receive_t.py  
in h1: ./st_py/send_t.py 10.0.2.1 "msg"  

2. probe test:  
make  
xterm h1 h2  
in h2: ./probe_py/p_receive_t.py  
in h1: ./probe_py/p_send_t.py  

3. cnt probe test  
make   
xterm h1 h2  
in h2: ./cnt_probe_py/p_receive_t.py   
in h1: ./cnt_probe_py/p_send_t.py    

## experiment

### Dataset preprocess
In our experiment, we use AOL dataset that collects user's url click records to test our CMS and Ada-CMS algorithm. Since the AOL datset is very large, we only use first 100 hours data and top 100 frequent query.

In preprocess, we will filter out first 100 hours and top100 frequent queries and also map query to TCP's dport. (We can't directly use string query)
1. Make sure file `user-ct-test-collection-02.txt` (AOL dataset) is under `dataset` directory. [Download link](http://www.cim.mcgill.ca/~dudek/206/Logs/AOL-user-ct-collection/user-ct-test-collection-02.txt.gz)

2. Under `dataset` directory, run 
    ```
    python3 pickle_query.py
    ``` 
    before running `preprocess.py` file if pickle file `query_2_dport.pkl` doesn't exist.

3. Under `dataset` directory, run 
    ```
    python3 preprocess.py
    ```
    if file `AOL_100t_top10.csv` and `AOL_100t_top100.csv` don't exist.

### Experiment
Under `count_min_sketch/experiment` directory.

1. Adjust parameters you want to experiment.
    ```
    const bit<16> CMS_TABLE_NUM = 4; //d of CMS
    const bit<16> CMS_TABLE_WIDTH = 128; //w of CMS
    TIME_ADAPTIVE = 1  // use time adaptive CMS  
    TIME_ADAPTIVE = 0  // not use time adaptive CMS  
    ```

2. Build
    ```
    make clean
    make
    xterm h1
    xterm h2
    ```

3. Send experiment traffic(top100 heavy query) data.
    ```
    //in h1
    python3 send_exp.py
    ```

4. Send & Receive prob(top10 heavy) data.
    ```
    //in h2
    python3 receive_prob.py

    //in h1
    python3 send_prob.py
    ```
    When colsing h2, prob result will be written to file `top10_prob_count.csv`

### Plot result
