#pragma once

#include "LocalHookBase.h"

namespace BrandenBone
{
    class BRANDENBONE_API NoClass { };

    template<typename Fn, class C>
    struct HookHandler;
}

#include "HookHandlerCdecl.h"

#ifndef USE64
#include "HookHandlerStdcall.h"
#include "HookHandlerThiscall.h"
#include "HookHandlerFastcall.h"
#endif