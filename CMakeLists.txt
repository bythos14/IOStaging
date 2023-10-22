cmake_minimum_required(VERSION 2.8)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(IOStaging C)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -O3 -nostdlib -fno-optimize-sibling-calls")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")


add_executable(iostaging
  src/main.c
  src/msif.c
  src/sdif.c
  src/common.h
)

target_link_libraries(iostaging
  taihenForKernel_stub
  taihenModuleUtils_stub
  SceCpuForDriver_stub
  SceSysclibForDriver_stub
  SceSysmemForDriver_stub
  SceThreadmgrForDriver_stub
  SceDebugForDriver_stub
  SceDmacmgrForDriver_stub
  ScePervasiveForDriver_stub
  SceIofilemgrForDriver_stub
  gcc
)

vita_create_self(iostaging.skprx iostaging CONFIG exports.yml UNSAFE)

# vita_create_stubs(stubs kubridge ${CMAKE_CURRENT_SOURCE_DIR}/exports.yml KERNEL)