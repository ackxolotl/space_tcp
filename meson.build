project('space_tcp',
    ['cpp'],
    meson_version : '>=0.54.0',
    default_options : [
        'cpp_std=c++2a',
        'optimization=s',
        'warning_level=3',
        'werror=false',
        'b_staticpic=false',
        'b_lto=true',
        'cpp_eh=none',
        'cpp_rtti=false',
    ],
    version: '2.29.1',
)

#####    RODOS Settings    #####

# Importing rodos, the target and target_file_ext is required for every build.
# Do not modify or remove the following lines!

rodos_prj = subproject('rodos',
                version : [
                    '>=202.1.29.1',
                    '<202.2.0.0',
                ])
rodos = subproject('rodos').get_variable('rodos')
target = subproject('rodos').get_variable('target')
target_file_ext = subproject('rodos').get_variable('target_file_ext')


#####    My Features    #####

# In this section the dependencies of the features provided by your subsystem
# are defined. For most others it is only required to include the one dependency
# (named after your subsystem) containing the include path as shown below.
# This enables them to use all your defined interfaces and communicate with your
# drivers and daemons.
# Note that you also have to use your own dependency when defining an executable.
# It should not be generally required to change the content of these lines!

#examples = []
#unit_tests = []
#hardware_tests = []
#interface_tests = []
#serial_devices = ['0','1','2','3','4','5','6','7','8','9','10','11', 'space_tcpv2_3','vorago_power_measurement_l4']

add_project_arguments('-D__rodos__', language : 'cpp')

space_tcp_inc = include_directories('include', 'src')
space_tcp_src = files('src/space_tcp.cpp')

space_tcp_lib = static_library('space_tcp',
    sources :               space_tcp_src,
    include_directories :   space_tcp_inc,
    dependencies : [
        rodos.partial_dependency(compile_args: true, includes: true),
    ]
)

space_tcp = declare_dependency(
    include_directories : space_tcp_inc,
    dependencies        : [
        rodos.partial_dependency(link_args: true, includes: true, links: true),
    ],
    link_with           : space_tcp_lib,
)
global_dep = space_tcp

space_tcp_src_dep = declare_dependency(
    sources             : space_tcp_src,
    include_directories : space_tcp_inc
)

space_tcp_executables = []


#####    My Examples    #####

# All examples and executables related to these examples (i.e. where you show
# how your code is used) should be defined within the 'examples' subdirectory.
# Examples are in most cases apps and executables that are used while developing
# and as a reference for others.
# Examples are only built if used as the top level project

if not meson.is_subproject()
    subdir('examples/rodos')
endif


#####    Tests    #####

# All tests (unit tests, interface tests, hardware tests) that can be executed
# automatically (and are written using gtest in most cases) should be defined
# within the 'tests' subdirectory.
# Examples are only built if used as the top level project
# Do not change or remove the lines below!

if not meson.is_subproject()
#    subdir('core/tests/module_tests')
#    subdir('common/support/unit_tests')
#    subdir('common/support/hardware_tests')
#    subdir('common/support/interface_tests')
endif


#####    Doxygen    #####

# This part is required to generate the code documentation using doxygen.
# Do not change or remove this part!

doxygen = find_program('doxygen', required : false)
if doxygen.found() and not meson.is_subproject()
    run_target('doxygen',
        command : [
            meson.source_root() + '/subprojects/rodos/scripts/build_doxygen.sh',
            meson.source_root() + '/subprojects/rodos/Doxyfile',
            'PROJECT_NAME = ' + meson.project_name(),
            'PROJECT_NUMBER = ' + meson.project_version(),
            'INPUT += src/'
        ]
    )
endif


#####    clang-format & clang-tidy    #####

# This part is required to automatically check clang-tidy and clang-format rules.
# Do not change or remove this part!

clang_format = find_program('clang-format', required : false)
if clang_format.found() and not meson.is_subproject()
    run_target('check-clang-format',
        command : [
            meson.source_root() + '/subprojects/rodos/scripts/clang-format.sh',
            meson.source_root() + '/subprojects/rodos/scripts/run-clang-format.py',
            '-style="{BasedOnStyle: webkit}"'
        ]
    )
endif

clang_tidy = find_program('clang-tidy', required : false)
gnu_parallel = find_program('parallel', required : false)
if clang_tidy.found() and gnu_parallel.found() and not meson.is_subproject()
    run_target('check-clang-tidy',
        command : [
            meson.source_root() + '/subprojects/rodos/scripts/clang-tidy.sh'
        ]
    )
endif


#####    release convenience target    #####

git = find_program('git', required : false)
space_tcp_release = find_program('scripts/space_tcp_release.sh', required : false)
if git.found() and space_tcp_release.found()
    run_target('space_tcp-release',
    command : [space_tcp_release, 'prepare', meson.build_root()])
    run_target('push-release',
    command : [space_tcp_release, 'push'])
endif

