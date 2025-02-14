#pragma once
#include <BrandenBone/Config.h>
#include <BrandenBone/Process/Process.h>
#include <BrandenBone/Process/MultPtr.hpp>
#include <BrandenBone/Process/RPC/RemoteFunction.hpp>
#include <BrandenBone/PE/PEImage.h>
#include <BrandenBone/Misc/Utils.h>
#include <BrandenBone/Misc/DynImport.h>
#include <BrandenBone/Syscalls/Syscall.h>
#include <BrandenBone/Patterns/PatternSearch.h>
#include <BrandenBone/Asm/LDasm.h>
#include <BrandenBone/localHook/VTableHook.hpp>
#include <BrandenBone/Symbols/SymbolLoader.h>

#include <iostream>
#include <CppUnitTest.h>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace BrandenBone;

constexpr wchar_t ModuleName[] = L"BrandenBoneTest.dll";

/// <summary>
/// Some extensions for Assert
/// </summary>
class AssertEx : public Assert
{
public:
    template <typename T>
    static void IsZero( const T& actual, const wchar_t* message = nullptr, const __LineInfo* pLineInfo = nullptr )
    {
        AssertEx::AreEqual( T( 0 ), actual, message, pLineInfo );
    }

    template <typename T>
    static void IsNotZero( const T& actual, const wchar_t* message = nullptr, const __LineInfo* pLineInfo = nullptr )
    {
        AssertEx::AreNotEqual( T( 0 ), actual, message, pLineInfo );
    }

    static void NtSuccess( NTSTATUS status, const wchar_t* message = nullptr, const __LineInfo* pLineInfo = nullptr )
    {
        AssertEx::IsTrue( status >= 0, message, pLineInfo );
    }
};

namespace Microsoft::VisualStudio::CppUnitTestFramework {
    template<> inline std::wstring ToString<AsmVariant::eType>( const AsmVariant::eType& t ) { RETURN_WIDE_STRING( t ); }
}

inline std::wstring GetTestHelperDir()
{
    wchar_t buf[MAX_PATH] = { };
    GetModuleFileNameW( GetModuleHandle( ModuleName ), buf, _countof( buf ) );
    std::wstring path = buf;
    if (path.empty())
        return path;

    // Get project root path
    for (int i = 0; i < 4; i++)
        path = Utils::GetParent( path );

    return path + L"\\Testing";
}

inline std::wstring GetTestHelperHost32()
{
    return GetTestHelperDir() + L"\\TestHelper32.exe";
}

inline std::wstring GetTestHelperHost64()
{
    return GetTestHelperDir() + L"\\TestHelper64.exe";
}

inline std::wstring GetTestHelperHost()
{
#ifdef USE64
    return GetTestHelperHost64();
#else
    return GetTestHelperHost32();
#endif
}

inline std::wstring GetTestHelperDll32()
{
    return GetTestHelperDir() + L"\\TestDll32.dll";
}

inline std::wstring GetTestHelperDll64()
{
    return GetTestHelperDir() + L"\\TestDll64.dll";
}

inline std::wstring GetTestHelperDll()
{
#ifdef USE64
    return GetTestHelperDll64();
#else
    return GetTestHelperDll32();
#endif
}
