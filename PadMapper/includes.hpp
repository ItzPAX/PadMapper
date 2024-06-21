#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <stdint.h>
#include <fileapi.h>
#include <wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

#include "portable_executable.hpp"
#include "utils.hpp"
#include "nt.hpp"
#include "intel_driver.hpp"
#include "winio.hpp"

#include "drv_utils.hpp"
#include "pt_utils.hpp"
#include "mapping_utils.hpp"