cmake_minimum_required(VERSION 3.14)
project(NoArch C)

set(TARGET noarch.out)
add_executable(${TARGET} main.c)

target_compile_options(${TARGET}
  PRIVATE
  -Wall
)

target_link_libraries(${TARGET} bfd)
