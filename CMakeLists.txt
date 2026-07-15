cmake_minimum_required(VERSION 3.20)
project(TrueWalletCollider LANGUAGES C CXX CUDA)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CUDA_STANDARD 17)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)

if(NOT DEFINED CMAKE_CUDA_ARCHITECTURES)
  set(CMAKE_CUDA_ARCHITECTURES "75;80;86;89;90")
endif()

# ---- GLFW ----
set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(GLFW_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/glfw)

# ---- Dear ImGui ----
set(IMGUI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/imgui)
add_library(imgui STATIC
  ${IMGUI_DIR}/imgui.cpp
  ${IMGUI_DIR}/imgui_draw.cpp
  ${IMGUI_DIR}/imgui_tables.cpp
  ${IMGUI_DIR}/imgui_widgets.cpp
  ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
  ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
)
target_include_directories(imgui PUBLIC
  ${IMGUI_DIR}
  ${IMGUI_DIR}/backends
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/glfw/deps
)
target_link_libraries(imgui PUBLIC glfw)
if(WIN32)
  target_link_libraries(imgui PUBLIC opengl32)
endif()

find_package(CUDAToolkit REQUIRED)

# micro-ecc (secp256k1) for dual-verify pubkey match
add_library(micro_ecc STATIC third_party/micro-ecc/uECC.c)
target_include_directories(micro_ecc PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/third_party/micro-ecc)
target_compile_definitions(micro_ecc PRIVATE
  uECC_SUPPORTS_secp160r1=0
  uECC_SUPPORTS_secp192r1=0
  uECC_SUPPORTS_secp224r1=0
  uECC_SUPPORTS_secp256r1=0
  uECC_SUPPORTS_secp256k1=1
  uECC_SUPPORT_COMPRESSED_POINT=1
)

add_executable(TrueWalletCollider
  src/main.cpp
  src/gui/App.cpp
  src/wallet/WalletDat.cpp
  src/wallet/Passphrase.cpp
  src/wallet/DualVerify.cpp
  src/wallet/HashcatExport.cpp
  src/wallet/PassphraseLab.cpp
  src/wallet/Salvage.cpp
  src/wallet/Archaeology.cpp
  src/wallet/Experiment.cpp
  src/wallet/ForensicVerify.cpp
  src/wallet/CaseManager.cpp
  src/wallet/ForensicTools.cpp
  src/wallet/ToolBridge.cpp
  src/wallet/CpuSimd.cpp
  src/wallet/BreakerRebuild.cpp
  src/wallet/OutsideBox.cpp
  src/wallet/ToolCatalog.cpp
  src/wallet/NativePipelines.cpp
  src/wallet/WalletFormat.cpp
  src/wallet/TrueReweave.cpp
  src/crack/CrackEngine.cpp
  src/crypto/crypto_wallet.cpp
  src/crypto/secp256k1_lite.cpp
  src/crypto/ctaes.c
  cuda/aes256_cuda.cu
)

target_include_directories(TrueWalletCollider PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto
  ${CMAKE_CURRENT_SOURCE_DIR}/cuda
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/glfw/deps
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/micro-ecc
  ${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES}
)

target_link_libraries(TrueWalletCollider PRIVATE
  imgui
  glfw
  micro_ecc
  CUDA::cudart
)

if(WIN32)
  target_link_libraries(TrueWalletCollider PRIVATE opengl32 comdlg32 shell32 ole32 winhttp)
  target_compile_definitions(TrueWalletCollider PRIVATE
    _CRT_SECURE_NO_WARNINGS
    GLFW_INCLUDE_NONE
  )
endif()

if(MSVC)
  target_compile_options(TrueWalletCollider PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:/W3 /O2 /EHsc /utf-8>
    $<$<COMPILE_LANGUAGE:C>:/W3 /O2>
    $<$<COMPILE_LANGUAGE:CUDA>:-Xcompiler=/W3,/O2>
  )
endif()

set_target_properties(TrueWalletCollider PROPERTIES
  CUDA_SEPARABLE_COMPILATION OFF
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}"
)

install(TARGETS TrueWalletCollider RUNTIME DESTINATION bin)
