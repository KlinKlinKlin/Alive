#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Author: n00B-ToT(shengta66396@163.com)

import logging , inspect

class ColoredFormatter(logging.Formatter):
    colors = {'black': 30,'red': 31,'green': 32,'yellow': 33,'blue': 34,'magenta': 35,'cyan': 36,'white': 37,'bgred': 41,'bggrey': 100 }
    mapping = {'INFO': 'cyan','WARNING': 'yellow','ERROR': 'red','CRITICAL': 'bgred','DEBUG': 'bggrey','SUCCESS': 'green'}
    prefix = '\033['
    suffix = '\033[0m'

    def colored(self, text, color=None):
        if color not in self.colors: color = 'white'
        return (self.prefix+'%dm%s'+self.suffix) % (self.colors[color], text)

    def format(self, record):
        log_fmt = self.colored(record.levelname, self.mapping.get(record.levelname, 'white'))+" - %(asctime)s - process: %(process)d - %(filename)s - %(name)s - %(lineno)d - %(module)s - %(message)s"
        return logging.Formatter(log_fmt).format(record)

def add_level(logger , level_name , level_num = 25  , cf_instance = ColoredFormatter() , cus_color = 100 ):
    handler = logging.StreamHandler()
    handler.setFormatter(cf_instance)
    level_name = level_name.upper()
    _low_level_name = level_name.lower()
    cf_instance.mapping.update({ level_name : 'custom_add' })
    cf_instance.colors.update({'custom_add':cus_color})
    logging.level_name = level_num
    logging.addLevelName(logging.level_name , level_name )
    setattr(logger ,_low_level_name ,  lambda message, *args: logger._log(logging.level_name, message, args))
    return logger

def get_filepath():
    """
    return {file}.log
    """
    filename = f"{'.'.join([i[1] for i in inspect.getouterframes(inspect.currentframe() , 2 ) ][-1].split('.')[:-1]) if '.'.join([i[1] for i in inspect.getouterframes(inspect.currentframe() , 2 ) ][-1].split('.')[:-1]) != '' else [i[1] for i in inspect.getouterframes(inspect.currentframe() , 2 ) ][-1].split('/')[-1]}"  + ".log"
    return f"{'.'.join(filename.split('.')[:-1])}.log"

def enable_filelog(logger , file_path = get_filepath()  ):
    file_handler = logging.FileHandler(filename = file_path,
            mode='a',
            encoding=None,
            delay=False,
            errors=None)
    file_format =  logging.Formatter("%(levelname)s - %(asctime)s - process: %(process)d - %(filename)s - %(name)s - %(lineno)d - %(module)s - %(message)s")
    file_handler.setLevel(level=logging.DEBUG)
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler )
    return logger

#  file_path = get_filepath()
def getLogger():
    """
    enable_filelog : filelog Flag(default False)
    file_path filelog path , default is {file}.log
    """
    # exec_file = [i[1] for i in inspect.getouterframes(inspect.currentframe() , 2 ) ][-1]
    exec_file = [i[1] for i in inspect.getouterframes(inspect.currentframe() , 2 ) ][-1].split('/')[-1].split('.')[0]
    logger = logging.getLogger(exec_file)
    handler = logging.StreamHandler()
    handler.setFormatter(ColoredFormatter())
    logger.addHandler(handler)
    logging.SUCCESS = 25 
    logging.addLevelName(logging.SUCCESS, 'SUCCESS')
    setattr(logger, 'success', lambda message, *args: logger._log(logging.SUCCESS, message, args))
    logger.setLevel(logging.INFO)
    return logger

