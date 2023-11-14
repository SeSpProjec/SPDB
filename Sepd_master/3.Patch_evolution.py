# -*- coding: UTF-8 -*-
from math import fabs
from random import random
import helpers.helper_zz as helper_zz
import helpers.src_parser as src_parser
import sys
import pickle
import copy
import os
import patch_varients
import configuration as config
from collections import Iterable
import random
import subprocess

# Original function: get_cveinfos
def extract_cve_details(patch_info, cve_id=None):
    detailed_cve_info = {}
    detailed_cve_info[cve_id] = []
    index_list = []
    with open(patch_info, 'r') as file:
        line_buffer = file.readlines()
    for line in line_buffer:
        if line.startswith("#"):  # Skipping commented lines
            continue
        cve, repo, commit = line[:-1].split(" ")
        index_list = (cve, repo, commit)
        detailed_cve_info[cve].append(index_list)
    return detailed_cve_info

def compute_file_difference(repo, branch, specific_commit, diff_file_name, func_dictionary, temp_file_name,
                            save_directory=config_settings.SAVE_PATCH_PATH):
    # Setting up paths
    save_directory = save_directory % (global_year, global_cve_id)
    base_path = save_directory + repo + "/" + branch + "/" + specific_commit + "_patch/"
    path_before_commit = base_path + "before_file/"
    path_after_commit = base_path + "after_file/"
    # Validating paths
    if not os.path.exists(save_directory) or not os.path.exists(base_path) or not os.path.exists(path_before_commit) or not os.path.exists(path_after_commit):
        return
    # Reading files in the directory
    files_before = os.listdir(path_before_commit)
    files_after = os.listdir(path_after_commit)
    # Generating patches using git diff
    index = 0
    is_first_commit_flag = 0  # Ensuring only one before commit difference is generated
    for file_before in files_before:
        # Skipping directories
        if os.path.isdir(path_before_commit + file_before):
            continue
        # Extracting file prefix
        file_before_prefix = os.path.splitext(file_before)[0]
        for file_after in files_after:
            index = files_after.index(file_after)
            file_after_prefix = os.path.splitext(file_after)[0]
            # Skipping if file name does not match
            if temp_file_name not in file_before:
                continue
            helper_utils.command("cd " + base_path + ";mkdir equal_file_patch")
            equal_patch_path = base_path + "equal_file_patch/"
            # Creating diff
            diff_command = "git diff " + path_before_commit + file_before + " " + path_after_commit + file_after + " > " + equal_patch_path + file_before_prefix[:4] + "_" + file_after_prefix[:4] + ".patch"
            diff_result = helper_utils.command(diff_command)
            patch_file, is_modified = filter_diff_function(diff_file_name, func_dictionary, diff_result)  # Filtering unrelated functions
            # Check if file is modified
            if is_modified:
                with open(equal_patch_path + file_before_prefix[:4] + "_" + file_after_prefix[:4] + ".patch", "w") as file:
                    file.writelines(patch_file)


# Original function: get_equal_filediff
def fetch_similar_file_differences(repo, branch, initial_commit, diff_file, func_map, save_directory=config_settings.SAVE_PATCH_PATH):
    save_directory = save_directory % (global_year, global_cve)
    common_directory = save_directory + repo + "/" + branch + "/" + initial_commit + "_patch/"
    before_directory = common_directory + "before_file/"
    after_directory = common_directory + "after_file/"
    temp_diff_file = diff_file.split("/")[-1]
    # Check path validity
    if not os.path.exists(save_directory) or not os.path.exists(common_directory) or not os.path.exists(before_directory) or not os.path.exists(after_directory):
        return
    files_after_commit = os.listdir(after_directory)
    # Loop to generate patch
    for file_after in files_after_commit:
        temp_after_path = after_directory + file_after + "/"
        if not os.path.exists(temp_after_path):
            continue
        # Extract prefix
        file_after_prefix = os.path.splitext(file_after)[0]
        file_before_patch = file_after_prefix[:4] + "_var"
        file_before_prefix = file_after_prefix[:4] + "_" + temp_diff_file.split(".")[0] + "_var"
        file_before_path = temp_after_path + file_before_prefix
        file_before_third = file_after_prefix[:4] + "_var"

        for index in range(6):
            helper_utils.command("cd " + common_directory + ";mkdir equal_file_patch")
            equal_patch_directory = common_directory + "equal_file_patch/" + file_after_prefix[:4] + "_var/"
            if not os.path.exists(equal_patch_directory):
                os.makedirs(equal_patch_directory)
            # Generate patch
            diff_command = "git diff " + file_before_path + str(index) + ".c" + " " + temp_after_path + file_after + "_patched_uD_" + temp_diff_file
            diff_result = helper_utils.command(diff_command)
            patch_file, is_modified = filter_diff_function(diff_file, func_map, diff_result)  # Filtering unrelated functions
            # Check if file is modified
            if is_modified:
                with open(equal_patch_directory + file_before_third + str(index) + ".patch", "a+") as file:
                    file.writelines(patch_file)
            # Process patch variants
            process_patch_variants(equal_patch_directory, file_before_patch, file_after_prefix, index)



# Original function: get_equal_funcdiff
def fetch_similar_func_differences(repo, branch, initial_commit, diff_file, func_map, save_directory=config_settings.SAVE_PATCH_PATH):
    # Check if function dictionary is empty
    if not func_map[diff_file]:
        return
    save_directory = save_directory % (global_year, global_cve)
    common_directory = save_directory + repo + "/" + branch + "/" + initial_commit + "_patch/"
    after_func_directory = common_directory + "after_func/"
    before_func_directory = common_directory + "before_func/"
    # Check path validity
    if not os.path.exists(save_directory) or not os.path.exists(common_directory) or not os.path.exists(before_func_directory) or not os.path.exists(after_func_directory):
        return
    # Read files in the directory
    files_after_commit = os.listdir(after_func_directory)
    # Generate patch for each file
    for file_after in files_after_commit:
        temp_after_path = after_func_directory + file_after + "/"
        if not os.path.exists(temp_after_path):
            continue
        # Extract file prefix
        file_after_func_prefix = os.path.splitext(file_after)[0]
        file_before_func_prefix = file_after_func_prefix[:4] + "_var"
        file_before_func_path = temp_after_path + file_before_func_prefix

        for index in range(6):
            helper_utils.command("cd " + common_directory + ";mkdir equal_func_patch")
            equal_func_directory = common_directory + "equal_func_patch/" + file_after_func_prefix[:4] + "_var/"
            if not os.path.exists(equal_func_directory):
                os.makedirs(equal_func_directory)
            # Generate diff
            diff_command = "git diff " + file_before_func_path + str(index) + ".c" + " " + temp_after_path + file_after + ".c"
            diff_result = helper_utils.command(diff_command)
            patch_file, is_modified = filter_diff_function(diff_file, func_map, diff_result)  # Filtering unrelated functions
            # Check if file is modified
            if is_modified:
                with open(equal_func_directory + file_before_func_prefix + str(index) + ".patch", "w") as file:
                    file.writelines(patch_file)
            # Process patch variants
            process_patch_variants(equal_func_directory, file_before_func_prefix, file_after_func_prefix, index)



# Original function: get_real_func_diff
def derive_actual_function_diff(repo, branch, commit_initial, diff_file_name, func_mapping, save_dir=config_settings.SAVE_PATCH_PATH):
    if not func_mapping[diff_file_name]:
        return
    save_dir = save_dir % (global_year, global_cve)
    common_dir = save_dir + repo + "/" + branch + "/" + commit_initial + "_patch/"
    after_func_dir = common_dir + "after_func/"
    before_func_dir = common_dir + "before_func/"

    if not os.path.exists(after_func_dir) or not os.path.exists(before_func_dir):
        return
    files_before = os.listdir(before_func_dir)
    files_after = os.listdir(after_func_dir)
    index = 0
    single_commit_flag = 0
    for file_before in files_before:
        if os.path.isdir(before_func_dir + file_before):
            continue
        if single_commit_flag == 1:
            break
        single_commit_flag += 1
        file_before_prefix = os.path.splitext(file_before)[0]
        for file_after in files_after:
            file_after_prefix = os.path.splitext(file_after)[0]
            file_after_complete = file_after + "/" + file_after + ".c"
            helper_utils.command("cd " + common_dir + ";mkdir equal_func_patch")
            equal_func_path = common_dir + "equal_func_patch/"
            diff_cmd = "git diff " + before_func_dir + file_before + " " + after_func_dir + file_after_complete
            diff_result = helper_utils.command(diff_cmd)
            patch_content, modified = filter_diff_function(diff_file_name, func_mapping, diff_result)
            if modified:
                with open(equal_func_path + file_before_prefix[:4] + "_" + file_after_prefix[:4] + ".patch", "w") as file:
                    file.writelines(patch_content)



def get_patch_var(equal_path,before_file_first,after_file_first,index=None):

    equal_path = equal_path +before_file_first + str(index)+".patch"
    if os.path.exists(equal_path)!=True:
        return # 前面已经新建了相关的文件

    # 对上述补丁做6种变换
    patch_varients.patcher(equal_path,index) #对与index相匹配的序号做对应的变换
    patch_file_names =  before_file_first +str(index)+ ".patch"
    # 打补丁
    patch_reset(equal_path,patch_file_names)

def patch_reset(equal_path,patch_file_names):
    if os.path.exists(equal_path)!=True:
        return
    #string = "cd " +equal_path;
    string ="patch -p1 < "+equal_path  #   +patch_file_names

    responce = helper_zz.command(string)
    return

def get_diff_func(diff_file_name,function_dic,diff_result):
    patch_file = []#定义一个列表
    flag= 0 #定义 如果遇到不同的行 则赋值为1，表示停止添加新的文件内容
    modify = 0
    for function_name in function_dic[diff_file_name]:#针对原patch的每一个函数
        for diff_line in diff_result:
            if diff_line.startswith("@@") and diff_line.find(function_name) == -1:
                flag = 1
                continue
            if diff_line.startswith("@@") and diff_line.find(function_name)!= -1:#遇到了相同的函数名，则后续部分都添加 且以@@开头
                modify = 1
                flag = 0
            if flag == 0:
                patch_file.append(diff_line)
    return patch_file,modify

# Original function: save_after_file
def store_file_after_patch(repo, branch, initial_commit, patched_commit, content_after, content_before, file_name, save_path=config_settings.SAVE_PATCH_PATH):
    save_path = save_path % (global_year, global_cve_id)
    save_directory = save_path + repo + "/" + branch + "/" + initial_commit + "_patch/" + "after_file/"
    save_directory = save_directory + patched_commit + "/"
    if not os.path.exists(save_directory):
        os.makedirs(save_directory)
    if not isinstance(content_after, Iterable) or not isinstance(content_before, Iterable):
        return
    with open(save_directory + patched_commit + "_patched_uD_" + file_name, 'w') as file:
        file.write("\n".join(content_after))
    for i in range(6):
        with open(save_directory + patched_commit[:4] + "_" + file_name.split(".")[0] + "_var" + str(i) + ".c", 'w') as file:
            file.write("\n".join(content_before))



# Original function: save_after_func
def store_functions_after_patch(repo, branch, initial_commit, post_patch_commit, pre_patch_commit, cve_id, commit_func_content, save_path=config_settings.SAVE_PATCH_PATH):
    save_path = save_path % (global_year, global_cve_id)
    save_dir = save_path + repo + "/" + branch + "/" + initial_commit + "_patch/" + "after_func/"
    save_var_dir = save_dir + post_patch_commit + "/"
    if not os.path.exists(save_var_dir):
        os.makedirs(save_var_dir)
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    if cve_id not in commit_func_content or 'aftercommits' not in commit_func_content[cve_id] or post_patch_commit not in commit_func_content[cve_id]['aftercommits']:
        return

    for element in commit_func_content[cve_id]['aftercommits'][post_patch_commit]:
        if not isinstance(commit_func_content[cve_id]['aftercommits'][post_patch_commit][element], Iterable):
            continue
        with open(save_var_dir + post_patch_commit + ".c", 'a+') as file:
            file.write("\n".join(commit_func_content[cve_id]['aftercommits'][post_patch_commit][element]))

    if cve_id not in commit_func_content or 'beforecommits' not in commit_func_content[cve_id] or pre_patch_commit not in commit_func_content[cve_id]['beforecommits']:
        return
    for i in range(6):
        if os.path.exists(save_var_dir + post_patch_commit[:4] + "_var" + str(i) + ".c"):
            continue
        for element in commit_func_content[cve_id]['aftercommits'][post_patch_commit]:
            if element not in commit_func_content[cve_id]['beforecommits'][pre_patch_commit]:
                continue
            if not isinstance(commit_func_content[cve_id]['beforecommits'][pre_patch_commit][element], Iterable):
                continue
            with open(save_var_dir + post_patch_commit[:4] + "_var" + str(i) + ".c", 'a+') as file:
                file.write("\n".join(commit_func_content[cve_id]['beforecommits'][pre_patch_commit][element]))


# Original function: save_before_func
def store_functions_before_patch(repo, branch, initial_commit, pre_patch_commit, cve_id, commit_func_content, save_path=config_settings.SAVE_PATCH_PATH):
    save_path = save_path % (global_year, global_cve_id)
    save_dir = save_path + repo + "/" + branch + "/" + initial_commit + "_patch/" + "before_func/"
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    if cve_id not in commit_func_content or 'beforecommits' not in commit_func_content[cve_id] or pre_patch_commit not in commit_func_content[cve_id]['beforecommits']:
        return

    for element in commit_func_content[cve_id]['beforecommits'][pre_patch_commit]:
        if not isinstance(commit_func_content[cve_id]['beforecommits'][pre_patch_commit][element], Iterable):
            continue
        with open(save_dir + pre_patch_commit + ".c", 'a+') as file:
            file.write("\n".join(commit_func_content[cve_id]['beforecommits'][pre_patch_commit][element]))


def save_before_file(repo, branch, yi_commit, beforepatchcommit, file_content, filename,save_path=config.SAVE_PATCH_PATH):
# Original function: save_before_file
def archive_file_prior_to_patch(repo, branch, initial_commit, pre_patch_commit, file_contents, file_name, save_directory=config_settings.PATCH_SAVE_PATH):
    save_directory = save_directory % (global_year, global_cve)
    directory_before_file = save_directory + repo + "/" + branch + "/" + initial_commit + "_patch/" + "before_file/"
    if not os.path.exists(directory_before_file):
        os.makedirs(directory_before_file)

    if not isinstance(file_contents, Iterable):
        return

    with open(directory_before_file + pre_patch_commit + "_prepatch_uD_" + file_name, 'w') as file:
        file.write("\n".join(file_contents))

def fetch_primary_file_commits_v2(repo_directory, branch, file_name):
    command_string = 'cd ' + repo_directory + ';git log --pretty=oneline --first-parent ' + branch + ' -- -p ' + file_name
    result_buffer = helper_utils.execute_command(command_string)
    primary_file_commits = []
    result_buffer.reverse()
    commit_length = int(len(result_buffer) * 0.2)
    index = 0
    count = 0
    for line in result_buffer:
        if len(result_buffer) < 100 or commit_length != 0 or count % commit_length == 0:
            commit_id = line[:12]
            primary_file_commits.append(commit_id)
            if index > 100 or len(primary_file_commits) > 100:
                break
            index += 1
        count += 1
    return primary_file_commits

def extract_primary_file_commits(repo_path, branch_name, filename):
    command_line = 'cd ' + repo_path + ';git log --pretty=oneline --first-parent ' + branch_name + ' -- -p ' + filename
    execution_result = helper_utils.execute_command(command_line)
    main_file_commits_list = []
    for line in execution_result:
        commit_identifier = line[:12]
        main_file_commits_list.append(commit_identifier)
    return main_file_commits_list

# Original function: get_afterpatchcommits
def identify_post_patch_commits(repo_directory, branch, filename, patch_commit):
    primary_commits = extract_primary_file_commits(repo_directory, branch, filename)
    if patch_commit not in primary_commits:
        print("Unexpected: Patch commit", patch_commit, "not in main commit history of", repo_directory, branch, filename)
        return None
    index = primary_commits.index(patch_commit)
    return primary_commits[index-1:]


def retrieve_negative_sample_files(repo, branch, neg_commits, repo_path, filename, func_dict, cve_id, main_commit, save_path=config_settings.PATCH_SAVE_PATH):
    element_content_cve_commit = {}
    element_content_cve_commit[cve_id] = {}
    element_content_cve_commit[cve_id]['pre_commit_functions'] = {}

    for pre_commit in neg_commits:
        if pre_commit not in element_content_cve_commit[cve_id]['pre_commit_functions']:
            element_content_cve_commit[cve_id]['pre_commit_functions'][pre_commit] = {}

        for func_name in func_dict[filename]:
            element = (filename, func_name)
            pre_commit_file_content = helper_utils.get_filecontent(repo_path, pre_commit, filename)
            pre_commit_func_content = src_parser.parse_function_content(pre_commit_file_content, func_name)

            if not pre_commit_func_content:
                continue
            element_content_cve_commit[cve_id]['pre_commit_functions'][pre_commit][element] = pre_commit_func_content
    store_negative_samples(repo, branch, main_commit, cve_id, element_content_cve_commit, save_path)


# Original function: save_negative_func
def store_negative_samples(repository, branch_identifier, init_commit, cve_identifier, commit_func_content, directory_path=config_settings.PATCH_SAVE_PATH):
    directory_path = directory_path % (global_year, global_cve_id)
    directory_neg_samples = directory_path + repository + "/" + branch_identifier + "/" + init_commit + "_patch/" + "pre_patch_functions/negative_samples/"
    if not os.path.exists(directory_neg_samples):
        os.makedirs(directory_neg_samples)

    if cve_identifier not in commit_func_content or 'pre_commit_functions' not in commit_func_content[cve_identifier]:
        return

    for pre_commit in commit_func_content[cve_identifier]['pre_commit_functions']:
        for element in commit_func_content[cve_identifier]['pre_commit_functions'][pre_commit]:
            if not isinstance(commit_func_content[cve_identifier]['pre_commit_functions'][pre_commit][element], Iterable):
                continue
            with open(directory_neg_samples + pre_commit + ".c", 'a') as file:
                file_content = "\n".join(commit_func_content[cve_identifier]['pre_commit_functions'][pre_commit][element])
                file.write(file_content)
    return

# Original function: Patch_save_singlecommit
def Archive_Single_Commit_Patches(repo, branch, patch_info_file, cve_id=None, output_dir=None, year=None):
    global output_dir_global, cve_global_id, repo_global, branch_global, year_global
    output_dir_global = output_dir
    cve_global_id = cve_id
    repo_global = repo
    branch_global = branch
    year_global = year

    repo_path = helper_utils.get_repository_path(repo)
    patch_info_data = helper_utils.extract_patch_info(patch_info_file, cve_id=cve_id)
    function_content_mapping = {}

    for (cve, orig_repo, orig_commit) in patch_info_data[cve_id]:
        orig_repo_path = helper_utils.get_repository_path(orig_repo)
        function_dictionary = helper_utils.get_functions_from_commit(orig_repo_path, orig_commit)
        function_content_mapping[cve] = {}
        for filename in function_dictionary:
            if not filename.endswith(".c"):
                continue
            after_commits = identify_post_patch_commits(repo_path, branch, filename, orig_commit)
            if not after_commits:
                continue
            for after_commit in after_commits:
                if after_commit not in function_content_mapping[cve]:
                    function_content_mapping[cve][after_commit] = {}
                for funcname in function_dictionary[filename]:
                    file_content = helper_utils.get_file_content(repo_path, after_commit, filename)
                    function_content = src_parser.parse_function(file_content, funcname)
                    if function_content:
                        function_content_mapping[cve][after_commit][funcname] = function_content



#input: [repo] [branch] [patches info file]
#input: patchlocator_result 
#output: dictionary cve-filename-funcname-funccontent
# Original function: Patchevolution_tracker
def Evolution_Tracker(repo_identifier, branch_identifier, patch_details_path, cve_ident=None, destination_dir=None, target_year=None):
    global dest_dir_global, cve_ident_global, repo_ident_global, branch_ident_global, target_year_global
    dest_dir_global = destination_dir
    target_year_global = target_year
    cve_ident_global = cve_ident
    repo_ident_global = repo_identifier
    branch_ident_global = branch_identifier

    print("Time Marker:", helper_utils.current_time())

    repo_path_ref = helper_utils.obtain_repo_path(repo_identifier)
    patch_information = helper_utils.fetch_patch_info(patch_details_path, cve_id=cve_ident)
    func_content_mapping = {}
    commit_element_mapping = {}

    for (current_cve, source_repo, commit_base) in patch_information[cve_ident]:
        path_of_repo = helper_utils.resolve_repo_path(source_repo)
        dict_of_functions = helper_utils.analyze_functions_commit(path_of_repo, commit_base)
        func_content_mapping[current_cve] = {}
        commit_element_mapping[current_cve] = {}
        commit_element_mapping[current_cve]['postcommits'] = {}

        patch_time_marker = helper_zz.retrieve_commit_time(repo_path_ref, commit_base)
        if patch_time_marker is None or None in chosen_commits:
            continue
        chosen_commit_index = 0
        filtered_chosen_commits = [commit[0] for commit in chosen_commits if commit[1] is not None and commit[1] > patch_time_marker]
        for commit in chosen_commits:
            if commit[1] is not None and commit[1] > patch_time_marker:
                filtered_chosen_commits.append(commit[0])
                chosen_commit_index += 1
        if len(chosen_commits) > 0:
            filtered_chosen_commits.append(chosen_commits[chosen_commit_index][0])

        print("Timestamp:", helper_zz.current_time(), current_cve)
        if os.path.exists(compile_path_result + branch_test+"/"+str(commit_base)+"Patches/"):
            return
        for file_name in dict_of_functions:
            if not file_name.endswith(".c"):
                continue
            commits_after_patch = identify_commits_after_patch(repo_path_ref, branch_identifier, file_name, commit_base)
            if commits_after_patch is None:
                commits_after_patch = filtered_chosen_commits
                commits_after_patch = commits_after_patch[:50]
            else:
                if len(commits_after_patch) >= 50:
                    commits_after_patch = commits_after_patch[:50]

            commit_count = 0
            after_file_buffer = str()
            before_file_buffer = str()
            temp_file_name = file_name
            function_save_flag = 0
            first_commit_reference = obtain_first_commit(repo_path_ref)
            print("Initial Commit:", first_commit_reference)

            for commit_post_patch in commits_after_patch:
                reset_commit_state(repo_path_ref, commit_post_patch)
                compile_flag = execute_compile_process(repo_path_ref)
                if compile_flag == 0:
                    continue

                print("Time Check:", helper_zz.current_time(), current_cve)
                if commit_post_patch not in commit_element_mapping[current_cve]['postcommits']:
                    commit_element_mapping[current_cve]['postcommits'][commit_post_patch] = {}

                for func_name in dict_of_functions[file_name]:
                    element_tuple = (file_name, func_name)
                    if element_tuple not in func_content_mapping[current_cve]:
                        func_content_mapping[current_cve][element_tuple] = set()
                    file_content_after = helper_zz.get_content_of_file(repo_path_ref, commit_post_patch, file_name)
                    function_content_after = src_parser.extract_function(file_content_after, func_name)

                    if len(function_content_after) == 0:
                        print(current_cve, repo_path_ref, commit_post_patch, file_name, func_name, 'does not exist')
                        function_content_after = "Empty"
                    commit_element_mapping[current_cve]['postcommits'][commit_post_patch][element_tuple] = function_content_after
                    function_save_flag = 1

                temp_file_name = file_name.split("/")[-1]
                compile_temp_path = None
                if function_save_flag == 1:
                    print("Marker:", helper_zz.current_time())
                    compile_temp_path = store_compiled_file(repo_path_ref, compile_path_result, commit_post_patch, file_name, commit_count, branch_identifier, commit_base)
                    commit_count += 1
                remove_compiled_files(compile_temp_path, repo_path_ref)

            print("Time Marker:", helper_zz.current_time(), current_cve)
            reset_commit_state(repo_path_ref, first_commit_reference)

    print("Execution Completed!!")
    print("Timestamp:", helper_zz.current_time())

    return function_save_flag

if __name__ == '__main__':
    repo = sys.argv[1]
    branch = sys.argv[2]
    patches_info = sys.argv[3]
    Evolution_tracker(repo, branch, patches_info)
