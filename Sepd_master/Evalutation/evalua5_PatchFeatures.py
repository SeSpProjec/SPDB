# -*- coding: UTF-8 -*-
# todo 为什么要注重add语句？
# todo 因为aftercommit方法引入了许多语句，这些语句在意义上等价于在软件开发过程中的定制化开发，所以需要强调add语句的前、后变化

import os
import re
import sys
import Levenshtein
import pandas as pd
import configuration as config
from insertlist import cve_info #类
from helpers import helper_zz
import random
# global path.
rootPath = './'

# securityPatch_Path = rootPath + '/security_patch/'
negPath = rootPath + '/random_commit/'
csvPath = config.SECURITY_PATTCH_RESULTS_PATH

# keyword definition.
MI_keyword = ["overflow", "leak", "buffer", "race", "integer", "null", "dereference", "free", "lock", "byte", \
			  "directory", "bound", "loop", "uninitialized", "stack", "memory","padding", "infinite", "double", \
			  "array", "capture", "pointer", "permission", "size", "length", "division", "crash", "key", "root", "leak"]

# arithmetic operations.算数运算符
ari_op2 = ["++", "--"]
ari_op1 = ["=", "+", "-", "*", "/", "%"]
# relational operations. 关系运算符
rel_op2 = ["==", "!=", ">=", "<="]
rel_op1 = [">", "<"]
# logical operations. 逻辑运算符
log_op2 = ["&&", "||"]
log_op1 = ["!", "not", "and", "or"]
# bit operations. 位运算符
bit_op2 = ["<<", ">>", "bitand", "bitor", "xor"]
bit_op1 = ["~", "&", "|", "^"]
# memory keywords. 内存关键字
mem_keyword = ["malloc", "calloc", "realloc", "free", "memset", "memcmp", "memcpy", "memmove", "sizeof", "new", "delete"]
# if keywords. if关键字
if_keyword = ["if", "else", "switch", "case", "&&", "||"]
# loop keywords. 循环关键字
loop_keyword = ["for", "while"]
# jump keywords. 跳转关键字
jump_keyword = ["break", "continue", "return", "goto", "throw", "assert"]
# C keywords.
c_keywords = ['auto', 'break', 'case', 'char', 'const', 'continue', 'default', 'do', 'double', 'else', 'enum', 'extern', \
			  'float', 'for', 'goto', 'if', 'inline', 'int', 'long', 'register', 'restrict', 'return', 'short', 'signed', \
			  'sizeof', 'static', 'struct', 'switch', 'typedef', 'union', 'unsigned', 'void', 'volatile', 'while', 'bool', \
			  'alignas', 'alignof', 'bool', 'complex', 'imaginary', 'noreturn', 'static_assert', 'thread_local']
# C++ keywords.
cpp_keywords = ['alignas', 'alignof', 'and', 'and_eq', 'asm', 'atomic_cancel', 'atomic_commit', 'atomic_noexcept', 'auto', \
				'bitand', 'bitor', 'bool', 'break', 'case', 'catch', 'char', 'char8_t', 'char16_t', 'char32_t', 'class', \
				'compl', 'concept', 'const', 'consteval', 'constexpr', 'const_cast', 'continue', 'co_await', 'co_return', \
				'co_yield', 'decltype', 'default', 'delete', 'do', 'double', 'dynamic_cast', 'else', 'enum', 'explicit', \
				'export', 'extern', 'false', 'float', 'for', 'friend', 'goto', 'if', 'import', 'inline', 'int', 'long', \
				'module', 'mutable', 'namespace', 'new', 'noexcept', 'not', 'not_eq', 'nullptr', 'operator', 'or', 'or_eq', \
				'private', 'protected', 'public', 'reflexpr', 'register', 'reinterpret_cast', 'requires', 'return', 'short', \
				'signed', 'sizeof', 'static', 'static_assert', 'static_cast', 'struct', 'switch', 'synchronized', 'template', \
				'this', 'thread_local', 'throw', 'true', 'try', 'typedef', 'typeid', 'typename', 'union', 'unsigned', 'using', \
				'virtual', 'void', 'volatile', 'wchar_t', 'while', 'xor', 'xor_eq', 'printf']
# dictionary keywords.
dir_keyword = ["\'\'", "\'.\'", "\'..\'", "\'/../\'", "\'../\'", "\'/..\'", "\'/\'", "\'\\\'", "\'/\\\'",\
				'\"\"', '\".\"', '\"..\"', '\"/../\"', '\"../\"', '\"/..\"', '\"/\"', '\"\\\"', "\'/\\\'"]
# race keywords.
race_keyword = ["release", "lock", "mutex", "unlock"]
# not keywords.
not_keyword = ["==0", "!=0", "==null", "!=null", "!"]

# define cache. 内存
name = []
label = []
MI = []
# diff, hunk, func number.
diff_num = []
hunk_num = []

# 统计数量
# line number.
line_num_total = []
line_num_net = [] # fixme net代表的是什么
line_num_del = []
line_num_add = []
# character number.
char_num_total = []
char_num_net = []
char_num_del = []
char_num_add = []

# if number.
if_num_total = []
if_num_net = []
if_num_del = []
if_num_add = []
#jump number.
jump_num_total = []
jump_num_net = []
jump_num_del = []
jump_num_add = []
# loop number.
loop_num_total = []
loop_num_net = []
loop_num_del = []
loop_num_add = []

# function_call number.
call_num_total = []
call_num_net = []
call_num_del = []
call_num_add = []
# modified function number.
func_num = []

# arithmetic number.
ari_num_total = []
ari_num_net = []
ari_num_del = []
ari_num_add = []
# relational number.
rel_num_total = []
rel_num_net = []
rel_num_del = []
rel_num_add = []
# logical number.
log_num_total = []
log_num_net = []
log_num_del = []
log_num_add = []
# bitwise number.
bit_num_total = []
bit_num_net = []
bit_num_del = []
bit_num_add = []

# memory number.
mem_num_total = []
mem_num_net = []
mem_num_del = []
mem_num_add = []

# variable number.
var_num_total = []
var_num_net = []
var_num_del = []
var_num_add = []
# global similarity.
global_sim = []
global_norm_sim = []
# dictionary number.
dir_num_total = []
dir_num_net = []
dir_num_del = []
dir_num_add = []
# others.
cap_num = []
race_num = []
not_zero = []
preprocess = []
test_file_name = ""


#查询patch_file和patch_func不为空的CVEID
def query_cveid():
	# 查询已有的CVE ID
	cve_save_lists = cve_info.query_notnull_cve()
	return cve_save_lists

#查询equal_commit相关信息
def query_equalcommit():
	Equalcommit_lists = cve_info.query_Equalcommit()
	return Equalcommit_lists

def main(): #main函数首先针对每一个cve的commit进行特征扫描、再进行整体特征统计
	mode = 3 #决定进行哪种扫描 0：originalcommit 1：equalcommit 2：aftercommit自然演化版本
	cve_count = 0
	if mode==0:

		for cve_list in query_cveid():#给定一个CVE ID
			# 1.先扫描来自NVD的commit
			securityPatch_Path = config.SECURITY_PATCH_PATH % str(cve_list)
			if os.path.exists(securityPatch_Path)!=True:
				continue
			# read the positive files (1).
			cnt = 1
			securityPatch_lists = os.listdir(securityPatch_Path)
			for patch_list in securityPatch_lists:
				test_file_name = patch_list
				originalcommit_path = os.path.join(securityPatch_Path,patch_list)
				#补丁文件如果行数过多 跳过！
				with open(originalcommit_path, 'r') as fp:
					# s_buf = f.readlines()
					originalcommit_contents = fp.readlines()
				if len(originalcommit_contents)>10000:
					continue
				Process(originalcommit_path, '1')
				cnt += 1
			#结果保存为csv
			cve_count = cve_count +1
		patchFeature_2csv(csvPath + 'orginal_commit_features'+str(cve_count)+'.csv')
		print(cve_list,"end!")

	if mode==1:#equalcommit
		Equalcommit_lists = query_equalcommit()
		for CVE_ID, Equal_commit, Owner, Repo_name in Equalcommit_lists:
			# 1.保存补丁文件
			repopath = helper_zz.get_repopath(Owner+"%"+Repo_name)
			equalcommit_file = helper_zz.get_commitfile(repopath, Equal_commit)
			SAVE_EQUALCOMMIT_PATH = config.SAVE_EQUALCOMMIT_PATH % (CVE_ID.split("-")[1],CVE_ID) # YEAR,CVE_ID
			helper_zz.save_Equalcommit_file(commit_file=equalcommit_file, save_path=SAVE_EQUALCOMMIT_PATH,commit=Equal_commit)

			# 2.扫描Equal_commit内容特征
			if len(equalcommit_file) > 10000:
				continue
			Process(SAVE_EQUALCOMMIT_PATH+str(Equal_commit), '1') #扫描特征
		patchFeature_2csv(csvPath + 'equal_commit_features.csv')

	if mode==2:#aftercommit :随机选择commit，个数为original+equal的平均数 、对所有的cveid的aftercommit进行特征提取，因为要和original、equal的和进行对比
		#1.
		after_commit_cveid = query_cveid()
		for cve_list in after_commit_cveid:  # 扫描所有的cve id
			year = cve_list.split("-")[1]
			#SAVE_PATCH_PATH = config.SAVE_PATCH_PATH %(str(year),str(cve_list))
			SAVE_PATCH_PATH = "./source1012/" + str(year) +"/" + str(cve_list) +"/"
			if os.path.exists(SAVE_PATCH_PATH)!=True:
				continue
			for CVE_REPO_LIST in os.listdir(SAVE_PATCH_PATH):  # REPO_ fixme：需要扫描多个sourcecode文件夹

				CVE_SAVE_PATH_BRANCH = SAVE_PATCH_PATH + CVE_REPO_LIST + "/"
				for CVE_BRANCH_LIST in os.listdir(CVE_SAVE_PATH_BRANCH):  # BRANCH fixme:只对branch进行一次扫描特征
					CVE_SAVE_PATH_PATCH = CVE_SAVE_PATH_BRANCH + CVE_BRANCH_LIST + "/"
					BRANCH_FLAG = 0  # fixme:只对branch进行一次扫描特征
					for CVE_COMMIT_LIST in os.listdir(CVE_SAVE_PATH_PATCH):  #PATCH
						AFTERCOMMIT_SAVE_PATH = CVE_SAVE_PATH_PATCH + CVE_COMMIT_LIST + "/equal_file_patch/"
						if os.path.exists(AFTERCOMMIT_SAVE_PATH)!=True:
							continue
						contra_commit_lists = os.listdir(AFTERCOMMIT_SAVE_PATH) # 打乱aftercommit，随机选取
						random.shuffle(contra_commit_lists)
						aftercommit_Count = 0
						for contra_commit_list in contra_commit_lists:
							if ".patch" not in contra_commit_list or aftercommit_Count > 5:
								continue
							Process(AFTERCOMMIT_SAVE_PATH + str(contra_commit_list), '1')
							aftercommit_Count = aftercommit_Count + 1
						BRANCH_FLAG = 1
					if BRANCH_FLAG == 1:
						break#跳出扫描下一个库
		patchFeature_2csv(csvPath + 'after_commit_features_'+str(len(after_commit_cveid))+"source1012"+'.csv')

	if mode==3:#patchdb的原始数据，用来作为对照组

		contra_commit_lists = os.listdir(config.RQ4_CONTRA_PATH) # 打乱aftercommit，随机选取
		for contra_commit_list in contra_commit_lists:
			Process(config.RQ4_CONTRA_PATH + str(contra_commit_list), '1')
			cve_count= cve_count+1
		Write2File(csvPath + 'contra_commit_features_'+str(cve_count) +'_V2.csv')
		# patchFeature_2csv(csvPath + 'contra_commit_features_'+str(cve_count) +'.csv')
	return

def Process(filename, goldtruth):
	# get the name and label
	name.append(filename)
	label.append(goldtruth)
	# get features.
	GetMutualInfo(filename)
	deletion, addition = GetDiffHunkFunc(filename)
	GetLineInfo(deletion, addition)
	GetCharInfo(deletion, addition)
	GetMemInfo(deletion, addition)
	GetIfInfo(deletion, addition)
	GetJumpInfo(deletion, addition)
	GetLoopInfo(deletion, addition)
	GetAriRelLogBit(deletion, addition)
	del_var_list, add_var_list = GetCallVar(deletion, addition)
	GetGlobalSim(deletion, addition)
	GetDirInfo(deletion, addition)
	GetCapInfo(del_var_list, add_var_list)
	GetRaceInfo(deletion, addition)
	GetNotZero(deletion, addition)
	GetPreprocess(deletion, addition)
	return

def GetMutualInfo(filename):
	# read file.
	# fp = open(filename, encoding='utf-8', errors='ignore')
	with open(filename, 'r') as fp:
		# s_buf = f.readlines()
		contents = fp.read()
	# get contents after Subject or before diff.
	i = contents.find("Subject:")
	if i > 0:
		j = contents.find("---\n")
		content = contents[i + 8:j - 1].lower()
	else:
		j = contents.find("\ndiff")
		content = contents[:j].lower()
	# get mutual information list.
	MI_list = ""
	for item in MI_keyword:
		MI_list += str(content.count(item)) + ','
	MI.append(MI_list)
	# close file.
	fp.close()
	return

def GetDiffHunkFunc(filename):
	# output initialize.
	deletion = []
	addition = []
	# temp variable.
	diff_n = 0
	hunk_n = 0
	func_list = []
	del_hunk = ""
	add_hunk = ""
	in_diff = 0
	# read file with lines.
	fp = open(filename, "r")
	while 1:
		line = fp.readline()
		if not line:
			break
		# if line begins with diff, set in_diff = 1.
		if line[:5] == "diff ":
			if (line[line.rfind('.') + 1:-1].lower() in ["c", "c++", "cpp", "h", "h++", "hpp", "cc", "hh", "cxx", "hxx"]) and ("test" not in line.lower()):
				diff_n += 1
				in_diff = 1
			else:
				in_diff = 0
		# if line in the diff part.
		if in_diff == 1:
			# if line begins with @@, get the function name.
			if line[:2] == "@@":
				if (len(line[line.rfind("@@") + 2:-1]) != 0) \
						and (line[line.rfind("@@") + 2:-1] not in func_list): #and line[-2:-1] == ')' 有的函数没右括号
					func_list.append(line[line.rfind("@@") + 2:-1])
			# if line begins with +, -, but not ++, --.
			if (line[:1] in ['+', '-']) and (line[:2] not in ["++", "--"]) and (line[:3] not in ["+++", "---"]):
				# if line begins with '/*', '*', '*/'.
				if "/*" or "*" or "*/" in line: #注释
					if ("*/" in line) and ("/*" not in line):
						line = ''
					elif (line[1:].lstrip()[:2] == "/*") or (line[1:].lstrip()[:1] == "*"):
						line = ''
					else:
						i = line.find("/*")
						if i > 0:
							line = line[:i] + "\n"
				# if line begins with '-'.
				if (line[:1] == '-') and (len(line[1:].strip()) != 0):
					del_hunk += line
				# if line begins with '+'
				if (line[:1] == '+') and (len(line[1:].strip()) != 0):
					add_hunk += line
			else:
				# if find a hunk.
				if len(del_hunk) + len(add_hunk) > 0:
					deletion.append(del_hunk)
					addition.append(add_hunk)
					hunk_n += 1
				del_hunk = ""
				add_hunk = ""
	# close the file.
	fp.close()
	# get diff, hunk, func number.
	diff_num.append(diff_n)
	hunk_num.append(hunk_n)
	func_num.append(len(func_list))
	return deletion, addition

def GetLineInfo(deletion, addition):
	# line
	del_line = 0
	add_line = 0
	# find all hunks.
	for i in range(len(deletion)):
		if (len(deletion[i]) != 0):
			del_line += deletion[i].count("\n-") + 1
		if (len(addition[i]) != 0):
			add_line += addition[i].count("\n+") + 1
	# statistic.
	line_num_total.append(add_line + del_line)
	line_num_net.append(add_line - del_line)
	line_num_del.append(del_line)
	line_num_add.append(add_line)
	return del_line, add_line

def GetCharInfo(deletion, addition):
	# char
	del_char = 0
	add_char = 0
	# find all hunks.
	for i in range(len(deletion)):
		if (len(deletion[i]) != 0):
			del_char += len(deletion[i]) - deletion[i].count('\n') - deletion[i].count('\r') - deletion[i].count('\t') - deletion[i].count(' ') - (deletion[i].count("\n-")+1)
		if (len(addition[i]) != 0):
			add_char += len(addition[i]) - addition[i].count('\n') - addition[i].count('\r') - addition[i].count('\t') - addition[i].count(' ') - (addition[i].count("\n+")+1)
	# statistic.
	char_num_total.append(add_char + del_char)
	char_num_net.append(add_char - del_char)
	char_num_del.append(del_char)
	char_num_add.append(add_char)
	return del_char, add_char

def GetMemInfo(deletion, addition):
	# memory information.
	del_mem = 0
	add_mem = 0
	# find all hunks.
	for i in range(len(deletion)):
		for item in mem_keyword:
			if item in deletion[i]:
				del_mem += deletion[i].count(item)
			if item in addition[i]:
				add_mem += addition[i].count(item)
	# statistic.
	mem_num_total.append(add_mem + del_mem)
	mem_num_net.append(add_mem - del_mem)
	mem_num_del.append(del_mem)
	mem_num_add.append(add_mem)
	return del_mem, add_mem

def GetIfInfo(deletion, addition):
	# if keyword
	del_if = 0
	add_if = 0
	# find all hunks.
	for i in range(len(deletion)):
		for item in if_keyword:
			if item in deletion[i]:
				del_if += deletion[i].count(item)
			if item in addition[i]:
				add_if += addition[i].count(item)
	# statistic.
	if_num_total.append(add_if + del_if)
	if_num_net.append(add_if - del_if)
	if_num_del.append(del_if)
	if_num_add.append(add_if)
	return del_if, add_if

def GetJumpInfo(deletion, addition):
	# jump keyword
	del_jump = 0
	add_jump = 0
	# find all hunks.
	for i in range(len(deletion)):
		for term in jump_keyword:
			if term in deletion[i]:
				del_jump += deletion[i].count(term)
			if term in addition[i]:
				add_jump += addition[i].count(term)
	# statistic.
	jump_num_total.append(add_jump + del_jump)
	jump_num_net.append(add_jump - del_jump)
	jump_num_del.append(del_jump)
	jump_num_add.append(add_jump)
	return del_jump, add_jump

def GetLoopInfo(deletion, addition):
	# loop keyword.
	del_loop = 0
	add_loop = 0
	# find all hunks.
	for i in range(len(deletion)):
		for item in loop_keyword:
			if item in deletion[i]:
				del_loop += deletion[i].count(item)
			if item in addition[i]:
				add_loop += addition[i].count(item)
	# statistic.
	loop_num_total.append(add_loop + del_loop)
	loop_num_net.append(add_loop - del_loop)
	loop_num_del.append(del_loop)
	loop_num_add.append(add_loop)
	return del_loop, add_loop

def GetAriRelLogBit(deletion, addition):
	# arithmetic.
	del_ari = 0
	add_ari = 0
	# relational.
	del_rel = 0
	add_rel = 0
	# logical.
	del_log = 0
	add_log = 0
	# bit.
	del_bit = 0
	add_bit = 0
	# find all hunks.
	for i in range(len(deletion)):
		tmp_del = deletion[i][1:].replace("\n-", '')
		tmp_add = addition[i][1:].replace("\n+", '')
		for item in ari_op2:
			del_ari += tmp_del.count(item)
			add_ari += tmp_add.count(item)
			tmp_del = tmp_del.replace(item, '')
			tmp_add = tmp_add.replace(item, '')
		for item in rel_op2:
			del_rel += tmp_del.count(item)
			add_rel += tmp_add.count(item)
			tmp_del = tmp_del.replace(item, '')
			tmp_add = tmp_add.replace(item, '')
		for item in log_op2:
			del_log += tmp_del.count(item)
			add_log += tmp_add.count(item)
			tmp_del = tmp_del.replace(item, '')
			tmp_add = tmp_add.replace(item, '')
		for item in bit_op2:
			del_bit += tmp_del.count(item)
			add_bit += tmp_add.count(item)
			tmp_del = tmp_del.replace(item, '')
			tmp_add = tmp_add.replace(item, '')
		for item in ari_op1:
			del_ari += tmp_del.count(item)
			add_ari += tmp_add.count(item)
			tmp_del = tmp_del.replace(item, '')
			tmp_add = tmp_add.replace(item, '')
		for item in rel_op1:
			del_rel += tmp_del.count(item)
			add_rel += tmp_add.count(item)
			tmp_del = tmp_del.replace(item, '')
			tmp_add = tmp_add.replace(item, '')
		for item in log_op1:
			del_log += tmp_del.count(item)
			add_log += tmp_add.count(item)
			tmp_del = tmp_del.replace(item, '')
			tmp_add = tmp_add.replace(item, '')
		for item in bit_op1:
			del_bit += tmp_del.count(item)
			add_bit += tmp_add.count(item)
			tmp_del = tmp_del.replace(item, '')
			tmp_add = tmp_add.replace(item, '')
	# arithmetic.
	ari_num_total.append(add_ari + del_ari)
	ari_num_net.append(add_ari - del_ari)
	ari_num_del.append(del_ari)
	ari_num_add.append(add_ari)
	# relational.
	rel_num_total.append(add_rel + del_rel)
	rel_num_net.append(add_rel - del_rel)
	rel_num_del.append(del_rel)
	rel_num_add.append(add_rel)
	# logical.
	log_num_total.append(add_log + del_log)
	log_num_net.append(add_log - del_log)
	log_num_del.append(del_log)
	log_num_add.append(add_log)
	# bit.
	bit_num_total.append(add_bit + del_bit)
	bit_num_net.append(add_bit - del_bit)
	bit_num_del.append(del_bit)
	bit_num_add.append(add_bit)
	return del_ari, add_ari, del_rel, add_rel, del_log, add_log, del_bit, add_bit

def GetCallVar(deletion, addition):
	# call and var
	del_func_list = []
	del_var_list = []
	add_func_list = []
	add_var_list = []
	# find all hunks.
	for i in range(len(deletion)):
		tmp_del = deletion[i]
		tmp_add = addition[i]
		# process tmp_del.
		pre_del = ""
		while 1:
			if "\n-" in tmp_del:
				i = tmp_del.find("\n-")
				line = tmp_del[1:i].lstrip()
				tmp_del = tmp_del[i + 1:]
			else:
				line = tmp_del[1:].lstrip()
				tmp_del = ''
			if line[:1] == '#':
				pass
			else:
				while (len(line) > 0):
					mark = re.match('[0-9a-zA-Z\_]+', line)
					if (mark):
						j = mark.end()
						del_var_list.append(line[:j])
						pre_del = line[:j]
						line = line[j:].lstrip()
					else:
						j = re.match('[^\w\s]+', line)
						if (j):
							j = j.end()
							if line[:j][:1] == '(' and re.match('[0-9a-zA-Z\_]+', pre_del):
								del_var_list.remove(pre_del)
								del_func_list.append(pre_del)
							pre_del = line[:j]
							line = line[j:].lstrip()
						else:
							break
			if len(tmp_del) == 0:
				break
		del_var_list = list(set(del_var_list))
		del_func_list = list(set(del_func_list))
		# process tmp_add.
		pre_add = ""
		while 1:
			if "\n+" in tmp_add:
				i = tmp_add.find("\n+")
				line = tmp_add[1:i].lstrip()
				tmp_add = tmp_add[i + 1:]
			else:
				line = tmp_add[1:].lstrip()
				tmp_add = ''
			if line[:1] == '#':
				pass
			else:
				while (len(line) > 0):
					mark = re.match('[0-9a-zA-Z\_]+', line)
					if (mark):
						j = mark.end()
						add_var_list.append(line[:j])
						pre_add = line[:j]
						line = line[j:].lstrip()
					else:
						j = re.match('[^\w\s]+', line)
						if (j):
							j = j.end()
							if line[:j][:1] == '(' and re.match('[0-9a-zA-Z\_]+', pre_add):
								add_var_list.remove(pre_add)
								add_func_list.append(pre_add)
							pre_add = line[:j]
							line = line[j:].lstrip()
						else:
							break
			if len(tmp_add) == 0:
				break
		add_var_list = list(set(add_var_list))
		add_func_list = list(set(add_func_list))
	# call statistic.
	call_num_total.append(len(list(set(del_func_list).union(set(add_func_list)).difference(set(c_keywords + cpp_keywords)))))
	call_num_net.append(len(list(set(add_func_list).difference(set(del_func_list + c_keywords + cpp_keywords)))))
	call_num_del.append(len(list(set(del_func_list).difference(set(c_keywords + cpp_keywords)))))
	call_num_add.append(len(list(set(add_func_list).difference(set(c_keywords + cpp_keywords)))))
	# var statistic.
	var_num_total.append(len(list(set(del_var_list).union(set(add_var_list)).difference(set(c_keywords + cpp_keywords)))))
	var_num_net.append(len(list(set(add_var_list).difference(set(del_var_list + c_keywords + cpp_keywords)))))
	var_num_del.append(len(list(set(del_var_list).difference(set(c_keywords + cpp_keywords)))))
	var_num_add.append(len(list(set(add_var_list).difference(set(c_keywords + cpp_keywords)))))
	return del_var_list, add_var_list

def GetGlobalSim(deletion, addition):
	# global similarity
	tmp_del = ""
	tmp_add = ""
	# find all hunks.
	for i in range(len(deletion)):
		tmp_del += deletion[i]
		tmp_add += addition[i]
	# statistic.
	tmp_del = tmp_del[1:].replace("\n-", '').replace("\n", '').replace("\r", '').replace("\t", '').replace(" ", '')
	tmp_add = tmp_add[1:].replace("\n+", '').replace("\n", '').replace("\r", '').replace("\t", '').replace(" ", '')
	global_sim.append(Levenshtein.distance(tmp_del, tmp_add))  # /(len(tmp_del)*1.0))
	# normalized statistic.
	tmp_del = re.sub(r"[A-Za-z0-9_\.]", 'x', tmp_del)
	tmp_add = re.sub(r"[A-Za-z0-9_\.]", 'x', tmp_add)
	tmp_del = re.sub(r"x*", 'x', tmp_del)
	tmp_add = re.sub(r"x*", 'x', tmp_add)
	global_norm_sim.append(Levenshtein.distance(tmp_del, tmp_add))  # /(len(tmp_del)*1.0))
	return tmp_del, tmp_add

def GetDirInfo(deletion, addition):
	# dir num
	del_dir = 0
	add_dir = 0
	# find all hunks.
	for i in range(len(deletion)):
		for item in dir_keyword:
			if item in deletion[i]:
				del_dir += deletion[i].count(item)
			if item in addition[i]:
				add_dir += addition[i].count(item)
	# statistic.
	dir_num_total.append(add_dir + del_dir)
	dir_num_net.append(add_dir - del_dir)
	dir_num_del.append(del_dir)
	dir_num_add.append(add_dir)
	return del_dir, add_dir

def GetCapInfo(del_var_list, add_var_list):
	# cap_num
	del_cap = []
	add_cap = []
	# match CapList.
	for item in del_var_list:
		if re.match('[A-Z\_]+', item):
			del_cap.append(item)
	for item in add_var_list:
		if re.match('[A-Z\_]+', item):
			add_cap.append(item)
	cap_num.append(len(list(set(add_cap).difference(set(del_cap + add_cap)))))
	return del_cap, add_cap

def GetRaceInfo(deletion, addition):
	# race num
	del_race = 0
	add_race = 0
	# find all hunks.
	for i in range(len(deletion)):
		for item in race_keyword:
			del_race += deletion[i].lower().count(item)
			add_race += addition[i].lower().count(item)
	race_num.append(add_race - del_race)
	return del_race, add_race

def GetNotZero(deletion, addition):
	# not zero
	del_not = 0
	add_not = 0
	# find all hunks.
	for i in range(len(deletion)):
		for item in not_keyword:
			del_not += deletion[i].lower().count(item)
			add_not += addition[i].lower().count(item)
	not_zero.append(add_not - del_not)
	return del_not, add_not

def GetPreprocess(deletion, addition):
	# preprocess statement
	del_pro = 0
	add_pro = 0
	# find all hunks.
	for i in range(len(deletion)):
		del_pro += deletion[i].replace("\n-", '').replace("\n", '').replace("\r", '').replace("\t", '').replace(" ", '').count("-#")
		add_pro += addition[i].replace("\n+", '').replace("\n", '').replace("\r", '').replace("\t", '').replace(" ", '').count("+#")
	preprocess.append(add_pro - del_pro)
	return del_pro, add_pro

# 将特征保存为CSV文件
def patchFeature_2csv(filename):
	dset = pd.DataFrame()

	dset['name'] = name
	dset['diff_num'] = diff_num
	dset['hunk_num'] = hunk_num
	dset['func_num'] = func_num

	# dset['line_num_total'] = line_num_total
	# dset['line_num_del'] = line_num_del
	# dset['line_num_add'] = line_num_add
	#
	# #字符数量
	# dset['字符_num_total'] = char_num_total
	# dset['字符_delete_num'] = char_num_del
	# dset['字符_add_num'] = char_num_add

	#内存关键字数量
	dset['Memoery_num_total'] = mem_num_total
	dset['Memoery_del_num'] = mem_num_del
	dset['Memoery_add_num'] = mem_num_add

	#条件语句数量
	dset['Conditions_num_total'] = if_num_total
	dset['Conditions_num_del'] = if_num_del
	dset['Conditions_num_add'] = if_num_add

	#跳转语句数量
	dset['Jump_num_total'] = jump_num_total
	dset['Jump_num_del'] = jump_num_del
	dset['Jump_num_add'] = jump_num_add

	#循环语句数量
	dset['Loop_num_total'] = loop_num_total
	dset['Loop_num_del'] = loop_num_del
	dset['Loop_num_add'] = loop_num_add

	#算数运算符数量
	dset['Arithmetic_num_total'] = ari_num_total
	dset['Arithmetic_num_del'] = ari_num_del
	dset['Arithmetic_num_add'] = ari_num_add

	#关系运算符
	dset['relation_num_total'] = rel_num_total
	dset['relation_num_del'] = rel_num_del
	dset['relation_num_add'] = rel_num_add

	#逻辑运算符
	dset['Logic_num_total'] = log_num_total
	dset['Logic_num_del'] = log_num_del
	dset['Logic_num_add'] = log_num_add

	#位操作运算符
	dset['bitwise_num_total'] = bit_num_total
	dset['bitwise_num_del'] = bit_num_del
	dset['bitwise_num_add'] = bit_num_add

	#函数调用运算符
	dset['Funccall_num_total'] = call_num_total
	dset['Funccall_num_del'] = call_num_del
	dset['Funccall_num_add'] = call_num_add

	#变量数量
	dset['Variables_num_total'] = var_num_total
	dset['Variables_num_del'] = var_num_del
	dset['Variables_num_add'] = var_num_add

	# #全局相似度
	# dset['全局_sim'] = global_sim
	# dset['全局正则化_sim'] = global_norm_sim

	# dset['cap_num'] = cap_num
	# dset['race_num'] = race_num
	# dset['not_zero'] = not_zero
	# dset['preprocess'] = preprocess

	dset.to_csv(filename)
	return
def Write2File(filename):
	# write to file
	dset = pd.DataFrame()

	dset['name'] = name
	dset['diff_num'] = diff_num
	dset['hunk_num'] = hunk_num
	dset['func_num'] = func_num

	dset['line_num_total'] = line_num_total
	dset['line_num_net'] = line_num_net
	dset['line_num_del'] = line_num_del
	dset['line_num_add'] = line_num_add

	dset['char_num_total'] = char_num_total
	dset['char_num_net'] = char_num_net
	dset['char_num_del'] = char_num_del
	dset['char_num_add'] = char_num_add

	dset['mem_num_total'] = mem_num_total
	dset['mem_num_net'] = mem_num_net
	dset['mem_num_del'] = mem_num_del
	dset['mem_num_add'] = mem_num_add

	dset['if_num_total'] = if_num_total
	dset['if_num_net'] = if_num_net
	dset['if_num_del'] = if_num_del
	dset['if_num_add'] = if_num_add

	dset['jump_num_total'] = jump_num_total
	dset['jump_num_net'] = jump_num_net
	dset['jump_num_del'] = jump_num_del
	dset['jump_num_add'] = jump_num_add

	dset['loop_num_total'] = loop_num_total
	dset['loop_num_net'] = loop_num_net
	dset['loop_num_del'] = loop_num_del
	dset['loop_num_add'] = loop_num_add

	dset['ari_num_total'] = ari_num_total
	dset['ari_num_net'] = ari_num_net
	dset['ari_num_del'] = ari_num_del
	dset['ari_num_add'] = ari_num_add

	dset['rel_num_total'] = rel_num_total
	dset['rel_num_net'] = rel_num_net
	dset['rel_num_del'] = rel_num_del
	dset['rel_num_add'] = rel_num_add

	dset['log_num_total'] = log_num_total
	dset['log_num_net'] = log_num_net
	dset['log_num_del'] = log_num_del
	dset['log_num_add'] = log_num_add

	dset['bit_num_total'] = bit_num_total
	dset['bit_num_net'] = bit_num_net
	dset['bit_num_del'] = bit_num_del
	dset['bit_num_add'] = bit_num_add

	dset['call_num_total'] = call_num_total
	dset['call_num_net'] = call_num_net
	dset['call_num_del'] = call_num_del
	dset['call_num_add'] = call_num_add

	dset['var_num_total'] = var_num_total
	dset['var_num_net'] = var_num_net
	dset['var_num_del'] = var_num_del
	dset['var_num_add'] = var_num_add

	dset['global_sim'] = global_sim
	dset['global_norm_sim'] = global_norm_sim

	dset['dir_num_total'] = dir_num_total
	dset['dir_num_net'] = dir_num_net
	dset['dir_num_del'] = dir_num_del
	dset['dir_num_add'] = dir_num_add

	dset['cap_num'] = cap_num
	dset['race_num'] = race_num
	dset['not_zero'] = not_zero
	dset['preprocess'] = preprocess

	dset.to_csv(filename)
	return

if __name__ == '__main__':
	main()
