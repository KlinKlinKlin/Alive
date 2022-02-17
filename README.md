# Alive

程序用作 信息收集

- db 用 mongodb
- 消息传输用 redis 
- 普通单域名任务 跑 大约 2-5 min，处理过程包括 域名收集、端口扫描、http 检测

----
```bash
python3 -m pip install virtualenv -i http://mirrors.aliyun.com/pypi/simple/ --trusted-host mirrors.aliyun.com
source venv/bin/activate
python3 recon.py target.com
```

----

#TODO
- airflow 分布式 、worker docker 制作、webserver worker 制作 [ ]
- 站点信息抓取 ( js link、ssl、web cms ) [ ]
