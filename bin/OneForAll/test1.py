from oneforall import OneForAll
from multiprocessing import Process , Manager





from pprint import pprint
manager = Manager()
return_dict = manager.dict()
p = Process(target = oneforall, args = ('bilibili.com' , return_dict ))
p.start()
p.join()
pprint(return_dict.values())