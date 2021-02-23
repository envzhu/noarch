cmake_minimum_required(VERSION 3.14)
project(NoArch C)

set(TARGET noarch.out)
add_executable(${TARGET} main.c)

add_compile_options(-Wall -lbfd)
