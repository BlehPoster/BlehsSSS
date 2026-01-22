import subprocess

def run(cmd):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    for line in iter(p.stdout.readline, b''):
        print(line)
    p.stdout.close()
    p.wait()

def run_conan():
    print('RUN CONAN')
    command = ['conan', 'install', 'conanfile.txt', '--build=missing', '-s', 'build_type=Debug']
    run(command)

def run_cmake():
    print('RUN CMAKE')
    command = [ 'cmake', '--preset', 'conan-default' ]
    run(command)


run_conan()
run_cmake()