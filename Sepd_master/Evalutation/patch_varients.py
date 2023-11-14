# -*- coding: UTF-8 -*-
#防止出现编码错误
#需要指定的变量
# old_path = './test/'
# new_path[i] = './test/new'+str(i)

from audioop import add
from hashlib import new
#from msilib import add_stream
from operator import ne
import re  # 导入re模块
import os  # 导入os模块
#import sys # 导入sys模块
import shutil

import helpers.helper_zz


#匹配if语句，并更改
def match_and_change0(index,line):
    pattern = re.compile(r'if \((.*)\)')
    old_string = pattern.findall(line)
    if (old_string != []):
        global flag
        flag = 1
        new_string = '_sys_ZERO || '+old_string[0]
        line = line.replace(old_string[0],new_string)
    return line

def match_and_change1(index,line):
    pattern = re.compile(r'if \((.*)\)')
    old_string = pattern.findall(line)
    if (old_string != []):
        global flag
        flag = 1
        new_string = '_sys_ONE || '+old_string[0]
        line = line.replace(old_string[0],new_string)
    return line

def match_and_change2(index,line):
    pattern1 = re.compile(r'if \((.*)\)') 
    pattern2 = re.compile(r'\)(.*)')
    pattern3 = re.compile(r'(.*) \(')


    old_string1 = pattern1.findall(line)#括号内的字段
    old_string2 = pattern2.findall(line)#if括号后的字段
    if old_string2 != []:
        while ")" in old_string2[0]:
            old_string2 = pattern2.findall(old_string2[0])
    if (old_string1 != []):
        global flag
        flag = 1
        new_string = ' {_SYS_VAL = 1;}'
        # temp_string用于匹配第一个左括号之前的一切字符串，再加上old_string1，再加上增加的字符串，就是变体规则2中的第二行  
        temp_string = pattern3.findall(line)
        #if temp_string != [] && old_string1 != []:
        line = temp_string[0]+r'('+old_string1[0]+r')'+new_string+'\n'

        # line = line.strip()
        # line = line + new_string+'\n'
    return line,old_string2

def match_and_change3(index,line):
    pattern1 = re.compile(r'if \((.*)\)')
    pattern2 = re.compile(r'\)(.*)')
    pattern3 = re.compile(r'(.*) \(')

    old_string1 = pattern1.findall(line)
    old_string2 = pattern2.findall(line)

    if old_string2 != []:
        while ")" in old_string2[0]:
            old_string2 = pattern2.findall(old_string2[0])

    if (old_string1 != []):
        global flag
        flag = 1
        new_string = ' {_SYS_VAL = 0;}'

        temp_string = pattern3.findall(line)
        #if temp_string != [] && old_string1 != []:
        line = temp_string[0]+r'('+old_string1[0]+r')'+new_string+'\n'
    return line,old_string2

def match_and_change4(index,line):
    pattern1 = re.compile(r'if \((.*) \)')
    pattern2 = re.compile(r'\)(.*)')
    pattern3 = re.compile(r'(.*) \(')

    old_string1 = pattern1.findall(line)
    old_string2 = pattern2.findall(line)

    if old_string2 != []:
        while ")" in old_string2[0]:
            old_string2 = pattern2.findall(old_string2[0])

    if (old_string1 != []):
        global flag
        flag = 1
        new_string = ' {_SYS_VAL = 1;}'
        temp_string = pattern3.findall(line)
        #if temp_string != [] && old_string1 != []:
        line = temp_string[0]+r'('+old_string1[0]+r')'+new_string+'\n'
    return line,old_string2

def match_and_change5(index,line):
    pattern1 = re.compile(r'if \((.*) \)')
    pattern2 = re.compile(r'\)(.*)')
    pattern3 = re.compile(r'(.*) \(')

    old_string1 = pattern1.findall(line)
    old_string2 = pattern2.findall(line)


    if old_string2 != []:
        while ")" in old_string2[0]:
            old_string2 = pattern2.findall(old_string2[0])

    if (old_string1 != []):
        global flag
        flag = 1
        new_string = ' {_SYS_VAL = 0;}'
        
        temp_string = pattern3.findall(line)
        #if temp_string != [] && old_string1 != []:
        line = temp_string[0]+r'('+old_string1[0]+r')'+new_string+'\n'

    return line,old_string2

#if __name__ == '__main__':  # 脚本独立运行，则其__name__属性值被自动设置为'__main__'
def patch_var(given_path,index_flag=None): #index_flag用来标识调用函数的patch的序号，符合对应序号的patch只做一次变换
    #  old_path  new_path分别为源文件和变体文件所在路径
    old_path = given_path
    #old_path = './test/'
    all_file_list = os.listdir(old_path) #旧patch下的所有pathch

    #  这里实现创建8个子文件夹，分别对应八种形式,每个文件夹复制之前的文件 ，并加后缀i(0-8)
    new_path = {}
    for file_name in all_file_list:   #i表示第i种变体方法

        if os.path.isdir(old_path+file_name):
            continue

        print(file_name.find("var"))
        if file_name.find("var")==True:  # 保证对已经修改过的pathch，不进行二次修改
            continue
        #if os.path.isdir(file_name)==True:
        #    continue
        #print"1"
        #os.mkdir(new_path[i])
        for i in range(6): #某一个patch名称
            if type(index_flag)==bool or index_flag != i:
                continue

            new_path[i] = given_path
            #new_path[i] = './test/' #不创建新文件夹，直接通过标识名称区分新patch

            #为当前patch新建变体文件夹
            new_path[i] = new_path[i] + os.path.splitext(file_name)[0] + "_var/"  # 新pathch的路径
            if os.path.exists(new_path[i])==False:
                os.mkdir(new_path[i])
            old_file_name = os.path.join(old_path, file_name) # 旧文件所在路径

            fname = os.path.splitext(file_name)[0]+"_var"+str(i)      #新文件夹里，每一个文件都在之前的文件名后面加i
            ftype = os.path.splitext(file_name)[1]
            new_file_name = fname+ftype
            new_file_name = new_path[i] +new_file_name
            shutil.copyfile(old_file_name, new_file_name) #文件复制操作，将old_file 复制进 new_file

    #从这里开始对每个文件夹中的文件进行替换
            with open(old_file_name, 'r') as fp:  # 如果读取不存在以'r'的文件，则会出现error错误提示
                allLines = fp.readlines()  # 调用readlines()方法来读取fp行数返回给它
            index = 0                      #表示读取文件的第index行
            totalLen = len(allLines)       #表示读取文件的总行数
            flag = 0                       #flag表示该patch是否有过变动，为0表示未变动
            while index < totalLen:  # 调用while语句判断index位置
                line = allLines[index]  # 定义一个变量求出allLines当前位置
                temp = line            #方便后面字符串模式匹配时得到if()种的语句，用于i =7  8
                if line.startswith("+")!=True :
                    index = index +1
                    continue
                if i == 0:
                    line = match_and_change0(index, line)  # 匹配if()语句，并更改
                    allLines[index] = line
                elif i == 1:
                    line = match_and_change1(index, line)
                    allLines[index] = line
                elif i == 2:
                    line = match_and_change2(index, line)  # 匹配if()语句，并更改
                    allLines[index] = line
                    pattern = re.compile(r'if \((.*)\)')  # 模式匹配规则
                    findresult = pattern.findall(temp)
                    if (findresult != []):
                        allLines.insert(index + 1, '+    if (_SYS_VAL) {\n')
                        index += 1
                elif i == 3:
                    line = match_and_change3(index, line)
                    allLines[index] = line
                    pattern = re.compile(r'if \((.*)\)')  # 模式匹配规则
                    findresult = pattern.findall(temp)
                    if (findresult != []):
                        allLines.insert(index + 1, '+    if (!_SYS_VAL) {\n')
                        index += 1
                elif i == 4:
                    line = match_and_change4(index, line)
                    allLines[index] = line
                    pattern = re.compile(r'if \((.*) \)')  # 模式匹配规则
                    findresult = pattern.findall(temp)
                    if (findresult != []):
                        var = findresult[0]  # 得到匹配字符串
                        allLines.insert(index + 1, '+    if (_SYS_VAL &&' + var + ') {\n')
                        index += 1
                elif i == 5:
                    line = match_and_change5(index, line)
                    allLines[index] = line
                    pattern = re.compile(r'if \((.*) \)')
                    findresult = pattern.findall(temp)
                    if (findresult != []):
                        var = findresult[0]
                        allLines.insert(index + 1, '+    if (_SYS_VAL || ' + var + ') {\n')
                        index += 1
                index += 1

            if flag == 1: #为1则表示patch变动过
                index_num = 0
                #该功能是增加静态变量的声明
                if i == 0:
                    while index_num < totalLen:
                        if allLines[index_num].startswith('+++'):
                            allLines.insert(index_num+1,'@@ -3,0 +3,1 @@\n')
                            allLines.insert(index_num+2,'+    const int _SYS_ZERO = 0;\n')
                        index_num+= 1
                if i == 1:
                    while index_num < totalLen:
                        if allLines[index_num].startswith('+++'):
                            allLines.insert(index_num+1,'@@ -3,0 +3,1 @@\n')
                            allLines.insert(index_num+2,'+    const int _SYS_ONE = 1;\n')
                        index_num += 1
                if i == 2:
                    while index_num < totalLen:
                        if allLines[index_num].startswith('+++'):
                            allLines.insert(index_num+1,'@@ -3,0 +3,1 @@\n')
                            allLines.insert(index_num+2,'+    int _SYS_VAL = 0;\n')
                        index_num += 1
                if i == 3:
                    while index_num < totalLen:
                        if allLines[index_num].startswith('+++'):
                            allLines.insert(index_num+1,'@@ -3,0 +3,1 @@\n')
                            allLines.insert(index_num+2,'+    int _SYS_VAL = 1;\n')
                        index_num += 1
                if i == 4:
                    while index_num < totalLen:
                        if allLines[index_num].startswith('+++'):
                            allLines.insert(index_num+1,'@@ -3,0 +3,1 @@\n')
                            allLines.insert(index_num+2,'+    int _SYS_VAL = 0;\n')
                        index_num += 1
                if i == 5:
                    while index_num < totalLen:
                        if allLines[index_num].startswith('+++'):
                            allLines.insert(index_num+1,'@@ -3,0 +3,1 @@\n')
                            allLines.insert(index_num+2,'+    int _SYS_VAL = 1;\n')
                        index_num += 1

            with open(new_file_name, 'w') as fp:
                fp.writelines(allLines)

#用的是这个
def patcher(given_path,index_flag=None):

        for i in range(6): #某一个patch名称
            if type(index_flag)==bool or index_flag != i:
                continue

            #new_path[i] = given_path
            #new_path[i] = './test/' #不创建新文件夹，直接通过标识名称区分新patch

            #为当前patch新建变体文件夹
            #new_path[i] = new_path[i] + os.path.splitext(file_name)[0] + "_var/"  # 新pathch的路径
            #if os.path.exists(new_path[i])==False:
            #    os.mkdir(new_path[i])
            #old_file_name = os.path.join(old_path, file_name) # 旧文件所在路径

            #fname = os.path.splitext(file_name)[0]+"_var"+str(i)      #新文件夹里，每一个文件都在之前的文件名后面加i
            #ftype = os.path.splitext(file_name)[1]
            #new_file_name = fname+ftype
            #new_file_name = new_path[i] +new_file_name
            #shutil.copyfile(old_file_name, new_file_name) #文件复制操作，将old_file 复制进 new_file
            old_file_name = given_path
            if os.path.exists(old_file_name)!=True:
                return
            new_file_name = old_file_name #直接覆盖写入
    #从这里开始对每个文件夹中的文件进行替换
            with open(old_file_name, 'r') as fp:  # 如果读取不存在以'r'的文件，则会出现error错误提示
                allLines = fp.readlines()  # 调用readlines()方法来读取fp行数返回给它
            #for num in range(20):
            #    allLines.append("\n")
            index = 0                      #表示读取文件的第index行
            totalLen = len(allLines)       #表示读取文件的总行数
            flag = 0                       #flag表示该patch是否有过变动，为0表示未变动
            while index < totalLen:  # 调用while语句判断index位置
                line = allLines[index]  # 定义一个变量求出allLines当前位置
                temp = line            #方便后面字符串模式匹配时得到if()种的语句，用于i =7  8
                if line.startswith("+")!=True :
                    index = index +1
                    continue
                if i == 0:
                    line = match_and_change0(index, line)  # 匹配if()语句，并更改
                    allLines[index] = line
                    flag = 1
                elif i == 1:
                    line = match_and_change1(index, line)
                    allLines[index] = line
                    flag = 1
                elif i == 2:
                    line,add_string = match_and_change2(index, line)  # 匹配if()语句，并更改
                    if add_string != []:            #这两句是为了减少error写的，没什么实际意义
                        add_string = add_string[0] #add_string是来自 if（）右边的全部字段
                    allLines[index] = line
                    pattern = re.compile(r'if \((.*)\)')  # 模式匹配规则
                    findresult = pattern.findall(temp)
                    if (findresult != []):
                        if flag==0:
                            allLines.insert(index,'+    int _SYS_VAL = 0;\n') #表示只在第一次匹配到if语句时候加入 变量定义 -1代表在if语句前
                            index += 1
                            allLines.insert(index+1, '+    if (_SYS_VAL) '+add_string+'\n')
                            allLines = helpers.helper_zz.change_patch_counts(allLines) #更新变化的行数
                            index += 1
                            flag = 1
                            totalLen += 2 #防止读不到所有的行
                        else:
                            allLines.insert(index+1, '+    if (_SYS_VAL) '+add_string+'\n')
                            allLines = helpers.helper_zz.change_patch_counts(allLines) #更新变化的行数
                            index += 1
                            totalLen +=1
                elif i == 3:
                    line,add_string = match_and_change3(index, line)
                    if add_string!=[]:
                        add_string = add_string[0]
                    allLines[index] = line
                    pattern = re.compile(r'if \((.*)\)')  # 模式匹配规则
                    findresult = pattern.findall(temp)
                    if (findresult != []):
                        if flag==0:
                            allLines.insert(index,'+    int _SYS_VAL = 1;\n')
                            index += 1
                            allLines.insert(index + 1, '+    if (!_SYS_VAL) '+add_string+"\n")
                            allLines = helpers.helper_zz.change_patch_counts(allLines)  # 更新变化的行数
                            index += 1
                            flag = 1
                            totalLen +=2
                        else:
                            allLines.insert(index + 1, '+    if (!_SYS_VAL) '+add_string+"\n")
                            allLines = helpers.helper_zz.change_patch_counts(allLines) #更新变化的行数
                            index += 1
                            totalLen +=1

                elif i == 4:
                    line,add_string = match_and_change4(index, line)
                    if add_string!=[]:
                        add_string = add_string[0]

                    allLines[index] = line
                    pattern = re.compile(r'if \((.*)\)')  # 模式匹配规则
                    findresult = pattern.findall(temp)
                    if (findresult != []):
                        if flag==0:
                            allLines.insert(index,'+    int _SYS_VAL = 0;\n')
                            index += 1
                            var = findresult[0]  # 得到匹配字符串
                            allLines.insert(index + 1, '+    if (_SYS_VAL &&' + var +")"+ add_string+'\n')
                            allLines = helpers.helper_zz.change_patch_counts(allLines)  # 更新变化的行数
                            index += 1
                            totalLen +=2
                            flag = 1
                        else:
                            allLines.insert(index + 1, '+    if (_SYS_VAL &&' + var + ")"+add_string+'\n')
                            allLines = helpers.helper_zz.change_patch_counts(allLines)  # 更新变化的行数
                            index += 1
                            totalLen +=1

                elif i == 5:
                    line,add_string = match_and_change5(index, line) #需要判断add_string的需要加入的位置
                    if add_string!=[]:
                        add_string = add_string[0]

                    allLines[index] = line
                    pattern = re.compile(r'if \((.*)\)')
                    findresult = pattern.findall(temp)
                    if (findresult != []):
                        if flag==0:
                            allLines.insert(index,"+    int _SYS_VAL = 1;\n")
                            index += 1
                            var = findresult[0]
                            allLines.insert(index + 1, '+    if (_SYS_VAL || ' + var +")"+ add_string+'\n')
                            allLines = helpers.helper_zz.change_patch_counts(allLines)  # 更新变化的行数
                            index += 1
                            flag = 1
                            totalLen +=2
                        else:
                            allLines.insert(index + 1, '+    if (_SYS_VAL || ' + var + ")"+ add_string+'\n')
                            allLines = helpers.helper_zz.change_patch_counts(allLines)  # 更新变化的行数
                            index += 1
                            flag = 1
                            totalLen +=1
                index += 1


            with open(new_file_name, 'w') as fp:
                fp.writelines(allLines)
