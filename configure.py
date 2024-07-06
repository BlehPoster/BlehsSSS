import subprocess

def print_result(result):
    if len(result.stdout) > 0:
        print("stdout:", result.stdout)
    if len(result.stderr) > 0:
        print("stderr:", result.stderr)

def run_conan():
    command = ['conan', 'install', 'conanfile.txt', '--build=missing']
    result = subprocess.run(command, capture_output=True, text=True)
    print_result(result)

run_conan()