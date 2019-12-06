# COMP536Project
## using P4 to do time-adaptive count min sketch  

probe_hdr: used to probe current heavy hitter  

h1: IP: 10.0.1.1	MAC: 00:00:00:01:01  
h2: IP: 10.0.1.2	MAC: 00:00:00:01:02  

st_py: structure test python files  
probe_py: probe python files  

## test  
under count_min_sketch folder  
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
