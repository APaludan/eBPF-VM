find_package(PkgConfig)
if(NOT PkgConfig_FOUND)
  message(
    FATAL_ERROR
      "\n❌ pkg-config not found.\n"
      "It is required to locate system libraries.\n\n" "Install it with:\n"
      "  Arch: sudo pacman -S pkgconf\n")
endif()

pkg_check_modules(LIBBPF libbpf>=0.7)
if(NOT LIBBPF_FOUND)
  message(FATAL_ERROR "\n❌ libbpf >= 0.7 not found (skeleton API required).\n"
                      "Install it with:\n" "  Arch: sudo pacman -S libbpf\n")
endif()


# add packages here
CPMAddPackage(
  NAME googletest
  GITHUB_REPOSITORY google/googletest
  VERSION 1.17.0
)
