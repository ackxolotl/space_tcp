# Examples

# If you create your own examples, place them into a subdirectory.
# Afterwards add them by adding a line similar to this:
# subdir('your_example_directory')

send_src = files('send.cpp')
send = declare_dependency(sources : send_src)

executable('send' + target_file_ext,
    dependencies : [send, space_tcp])

