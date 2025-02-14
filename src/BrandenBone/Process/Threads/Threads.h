#pragma once

#include "../../Include/Winheaders.h"
#include "Thread.h"

#include <vector>
#include <mutex>

namespace BrandenBone
{

class ProcessThreads
{
public:
    BRANDENBONE_API ProcessThreads( class ProcessCore& core );
    BRANDENBONE_API ~ProcessThreads();

    ProcessThreads( const ProcessThreads& ) = delete;
    ProcessThreads& operator =( const ProcessThreads& ) = delete;

    /// <summary>
    /// Create the thread.
    /// </summary>
    /// <param name="threadProc">Thread enty point</param>
    /// <param name="arg">Thread argument.</param>
    /// <param name="flags">Thread creation flags</param>
    /// <returns>New thread object</returns>
    BRANDENBONE_API call_result_t<ThreadPtr> CreateNew(
        ptr_t threadProc,
        ptr_t arg,
        enum CreateThreadFlags flags = static_cast<CreateThreadFlags>(0)
    );

    /// <summary>
    /// Gets all process threads
    /// </summary>
    /// <returns>Threads collection</returns>
    BRANDENBONE_API std::vector<ThreadPtr> getAll() const;

    /// <summary>
    /// Get main process thread
    /// </summary>
    /// <returns>Pointer to thread object, nullptr if failed</returns>
    BRANDENBONE_API ThreadPtr getMain() const;

    /// <summary>
    /// Get least executed thread
    /// </summary>
    /// <returns>Pointer to thread object, nullptr if failed</returns>
    BRANDENBONE_API ThreadPtr getLeastExecuted() const;

    /// <summary>
    /// Get most executed thread
    /// </summary>
    /// <returns>Pointer to thread object, nullptr if failed</returns>
    BRANDENBONE_API ThreadPtr getMostExecuted() const;

    /// <summary>
    /// Get random thread
    /// </summary>
    /// <returns>Pointer to thread object, nullptr if failed</returns>
    BRANDENBONE_API ThreadPtr getRandom() const;

    /// <summary>
    /// Get thread by ID
    /// </summary>
    /// <param name="id">Thread ID</param>
    /// <returns>Pointer to thread object, nullptr if failed</returns>
    BRANDENBONE_API ThreadPtr get( DWORD id ) const;

private:
    class ProcessCore& _core;   // Core process functions
};

}