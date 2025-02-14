#pragma once

// Lib/Dll switch
#if !defined(BrandenBone_EXPORTS) && !defined(BrandenBone_IMPORTS) && !defined(BrandenBone_STATIC)
#define BrandenBone_STATIC
#endif

#if defined(_MSC_VER)

    #ifndef COMPILER_MSVC
        #define COMPILER_MSVC 1
    #endif

    #if defined(BrandenBone_IMPORTS)
        #define BRANDENBONE_API __declspec(dllimport)
    #elif defined(BrandenBone_EXPORTS)
        #define BRANDENBONE_API __declspec(dllexport)
    #else
        #define BRANDENBONE_API
    #endif

#elif defined(__GNUC__)
    #define COMPILER_GCC
    #define BRANDENBONE_API
#else
    #error "Unknown or unsupported compiler"
#endif

// No IA64 support
#if defined (_M_AMD64) || defined (__x86_64__)
    #define USE64
#elif defined (_M_IX86) || defined (__i386__)
    #define USE32
#else
    #error "Unknown or unsupported platform"
#endif


