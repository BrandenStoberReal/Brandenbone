#pragma once

#include <cstdio>
#include <cstdlib>

#pragma warning(push)
#pragma warning(disable : 4091)
#include <DbgHelp.h>
#pragma warning(pop)

namespace BrandenBone
{
#ifndef BrandenBone_NO_TRACE

inline void DoTraceV( const char* fmt, va_list va_args )
{
    char buf[2048], userbuf[1024];
    vsprintf_s( userbuf, fmt, va_args );
    sprintf_s( buf, "BrandenBone: %s\r\n", userbuf );
    OutputDebugStringA( buf );

#ifdef CONSOLE_TRACE
    printf_s( buf );
#endif
}

inline void DoTraceV( const wchar_t* fmt, va_list va_args )
{
    wchar_t buf[2048], userbuf[1024];
    vswprintf_s( userbuf, fmt, va_args );
    swprintf_s( buf, L"BrandenBone: %ls\r\n", userbuf );
    OutputDebugStringW( buf );

#ifdef CONSOLE_TRACE
    wprintf_s( buf );
#endif
}

template<typename Ch>
inline void DoTrace( const Ch* fmt, ... )
{
    va_list va_args;
    va_start( va_args, fmt );
    DoTraceV( fmt, va_args );
    va_end( va_args );
}

#define BrandenBone_TRACE(fmt, ...) DoTrace(fmt, ##__VA_ARGS__)

#else
#define BrandenBone_TRACE(...)
#endif

}