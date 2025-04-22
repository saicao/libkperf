#pragma once
#include <TargetConditionals.h>
#if TARGET_OS_IOS
#include "kdebug_ios.h"
#else
#include <sys/kdebug.h>
#endif