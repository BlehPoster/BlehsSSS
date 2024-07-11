import subprocess

def run(cmd):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    for line in iter(p.stdout.readline, b''):
        print(line)
    p.stdout.close()
    p.wait()

def run_conan():
    print('RUN CONAN')
    command = ['conan', 'install', 'conanfile.txt', '--build=missing']
    run(command)

def run_cmake():
    print('RUN CMAKE')
    command = ['cmake', '-B', 'out']
    run(command)

run_conan()
run_cmake()