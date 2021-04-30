find_package(Doxygen REQUIRED)

# set the input and output documentation paths
set(DOXYGEN_INPUT_DIR ${PROJECT_SOURCE_DIR})
set(DOXYGEN_OUTPUT_DIR ${PROJECT_BINARY_DIR}/doc)

# see if we can generate the CHM documentation
set(DOXYGEN_HHC_PROGRAM)
set(DOXYGEN_GENERATE_HTMLHELP NO)

# configure the source Doxyfile by copying it and replacing all @variables@
set(DOXYGEN_CONFIGURED_INPUT ${DOXYGEN_OUTPUT_DIR}/doxyfile)
configure_file(${DOXYGEN_INPUT_DIR}/doc/doxyfile.in ${DOXYGEN_CONFIGURED_INPUT} @ONLY)
configure_file(${DOXYGEN_INPUT_DIR}/doc/header.html.in ${DOXYGEN_OUTPUT_DIR}/header.html @ONLY)

# copy the files needed by the documentation
configure_file(${DOXYGEN_INPUT_DIR}/doc/doxygen.css ${DOXYGEN_OUTPUT_DIR}/html/doxygen.css COPYONLY)

# target setup
add_custom_target(doc ALL
                  COMMAND ${CMAKE_COMMAND} -E echo_append "Building API Documentation..."
                  COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_CONFIGURED_INPUT}
                  COMMAND ${CMAKE_COMMAND} -E echo "Done."
                  WORKING_DIRECTORY ${DOXYGEN_INPUT_DIR})

# setup install rules
#install(FILES ${DOXYGEN_OUTPUT_DIR}/SFML.tag
#        DESTINATION ${CMAKE_INSTALL_DOCDIR}
#        COMPONENT doc)
#install(DIRECTORY ${DOXYGEN_OUTPUT_DIR}/html
#        DESTINATION ${CMAKE_INSTALL_DOCDIR}
#        COMPONENT doc)
