/*
 * The contents of this file are subject to the AOLserver Public License
 * Version 1.1 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://aolserver.com/.
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * The Original Code is AOLserver Code and related documentation
 * distributed by AOL.
 *
 * The Initial Developer of the Original Code is America Online,
 * Inc. Portions created by AOL are Copyright (C) 1999 America Online,
 * Inc. All Rights Reserved.
 *
 * Alternatively, the contents of this file may be used under the terms
 * of the GNU General Public License (the "GPL"), in which case the
 * provisions of GPL are applicable instead of those above.  If you wish
 * to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the
 * License, indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by the GPL.
 * If you do not delete the provisions above, a recipient may use your
 * version of this file under either the License or the GPL.
 */

/*
 * nsldap.c --
 *
 *      A LDAP interface for NaviServer
 *
 */

#include <ns.h>
#include <lber.h>
#include <ldap.h>

#define NSLDAP_VERSION  "1.0d1"

#define CONFIG_USER     "user"          /* LDAP default bind DN */
#define CONFIG_PASS     "password"      /* DN password */
#define CONFIG_HOST     "host"          /* LDAP server */
#define CONFIG_CONNS    "connections"   /* Number of LDAP connections. */
#define CONFIG_VERBOSE  "verbose"       /* Log LDAP queries and errors */

/*
 * The Ns_ModuleVersion variable is required.
 */
NS_EXTERN const int Ns_ModuleVersion;
NS_EXPORT const int Ns_ModuleVersion = 1;

struct Handle;

typedef struct Pool {
    const char    *name;
    const char    *desc;
    const char    *host;
    int            port;
    const char    *user;
    const char    *pass;
    Ns_Mutex       lock;
    Ns_Cond        waitCond;
    Ns_Cond        getCond;
    int            waiting;
    int            nhandles;
    struct Handle *firstPtr;
    struct Handle *lastPtr;
    time_t         maxidle;
    time_t         maxopen;
    int            stale_on_close;
    bool           fVerbose;
} Pool;

typedef struct Handle {
    const char   *host;
    int           port;
    const char   *user;
    const char   *password;
    LDAP         *ldaph;
    LDAPMessage  *ldapmessageh;
    Ns_DString    ErrorMsg;
    const char   *poolname;
    int           connected;
    struct Handle *nextPtr;
    struct Pool   *poolPtr;
    time_t         otime;
    time_t         atime;
    int            stale;
    int            stale_on_close;
    int            verbose;
    uintptr_t      ThreadId;
} Handle;


/* Context we save */

typedef struct Context {
    Tcl_HashTable  poolsTable;
    Tcl_HashTable  activeHandles;
    const char    *defaultPool;
    char          *allowedPools;
} Context;

static struct timeval timeout = {
    120, 0
};

/*
 * Local functions defined in this file
 */

static int
BadArgs(Tcl_Interp *interp, const char **argv, const char *args);

static void
LDAPEnterHandle(Tcl_Interp *interp, Handle *handle, Context *context);

int
LDAPBouncePool(const char *pool, Context *context);

static void
LDAPCheckPool(Pool *poolPtr);

static Ns_SchedProc LDAPCheckPools;
static Tcl_CmdProc LDAPCmd;

static int
LDAPConnect(Handle *handlePtr);

static Pool *
LDAPCreatePool(const char *pool, const char *path);

void
LDAPDisconnect(Handle *handle);

static void
LDAPFreeCounts(void *arg);

static Pool *
LDAPGetPool(const char *pool, Context *context);

static int
LDAPIncrCount(Pool *poolPtr, int incr);

static Ns_TclTraceProc LDAPInterpInit;

static int
LDAPIsStale(Handle *handlePtr, time_t now);

int
LDAPPoolAllowable(Context *context, const char *pool);

void
LDAPPoolPutHandle(Handle *handle);

static int
LDAPGetHandle(Tcl_Interp *interp, const char *handleId, Handle **handle,
              Tcl_HashEntry **hPtrPtr, Context *context);
int
LDAPPoolTimedGetMultipleHandles(Handle **handles, const char *pool,
                                int nwant, int wait, Context *context);
static void
LDAPReturnHandle(Handle *handlePtr);

NS_EXPORT Ns_ModuleInitProc Ns_ModuleInit;
static Ns_TraceProc ReleaseLDAP;


/*
 *----------------------------------------------------------------------
 *
 * Ns_ModuleInit --
 *
 *      This is the module's entry point.  NaviServer runs this
 *      function right after the module is loaded.  It is used to read
 *      configuration data, initialize data structures, kick off the
 *      Tcl initialization function (if any), and do other things at
 *      startup.
 *
 * Results:
 *	NS_OK or NS_ERROR
 *
 * Side effects:
 *	Module loads and initializes itself.
 *
 *----------------------------------------------------------------------
 */

NS_EXPORT int
Ns_ModuleInit(const char *hServer, const char *UNUSED(hModule))
{
    Tcl_HashEntry  *hPtr;
    Tcl_HashSearch  search;
    Pool           *poolPtr;
    Ns_Set         *pools;
    Ns_DString      ds;
    const char     *pool, *path, *allowed;
    register char  *p;
    int             new, tcheck;
    Context        *context;

    /* Get Memory for the new Context */

    context = ns_malloc(sizeof(Context));

    Ns_DStringInit(&ds);
    Tcl_InitHashTable(&context->poolsTable, TCL_STRING_KEYS);
    Tcl_InitHashTable(&context->activeHandles, TCL_STRING_KEYS);

    /*
     * Add the allowed pools to the poolsTable
     */

    path = Ns_ConfigGetPath(hServer, NULL, "ldap", NULL);
    allowed = Ns_ConfigGetValue(path, "pools");
    context->defaultPool = Ns_ConfigGetValue(path, "defaultpool");

    pools = Ns_ConfigGetSection("ns/ldap/pools");
    if (pools != NULL && allowed != NULL) {
        if (STREQ(allowed, "*")) {
            size_t i;

            for (i = 0; i < Ns_SetSize(pools); ++i) {
                pool = Ns_SetKey(pools, i);
                Ns_Log(Debug, "nsldap: allowing * -> pool %s", pool);
                Tcl_CreateHashEntry(&context->poolsTable, pool, &new);
            }
        } else {
            p = (char *)allowed;
            while (p != NULL && *p != '\0') {
                p = strchr(allowed, ',');
                if (p != NULL) {
                    *p = '\0';
                }
                Ns_Log(Debug, "nsldap: allowing pool %s", allowed);
                Tcl_CreateHashEntry(&context->poolsTable, allowed, &new);
                if (p != NULL) {
                    *p++ = ',';
                }
                allowed = p;
            }
        }
    }

    /*
     * Attempt to create an ldap pool for each entry in the poolsTable
     */

    hPtr = Tcl_FirstHashEntry(&context->poolsTable, &search);
    while (hPtr != NULL) {
        pool = Tcl_GetHashKey(&context->poolsTable, hPtr);
        path = Ns_ConfigGetPath(NULL, NULL, "ldap", "pool", pool, NULL);
        poolPtr = NULL;
        poolPtr = LDAPCreatePool(pool, path);
        if (poolPtr != NULL) {
            Tcl_SetHashValue(hPtr, poolPtr);
        } else {
            Tcl_DeleteHashEntry(hPtr);
        }
        hPtr = Tcl_NextHashEntry(&search);
    }

    /*
     * Verify the default pool exists, if any
     */

    if (context->defaultPool != NULL) {
        hPtr = Tcl_FindHashEntry(&context->poolsTable,
                                 context->defaultPool);
        if (hPtr == NULL) {
            Ns_Log(Error, "nsldap: no such default pool '%s'",
                   context->defaultPool);
            context->defaultPool = NULL;
        }
    }

    /*
     * Construct the allowedPools list and initialize the nsldap Tcl
     * commands if any pools were actually created
     */

    if (context->poolsTable.numEntries == 0) {
        Ns_Log(Debug, "nsldap: no configured pools");
        context->allowedPools = (char*)"";
    } else {
        tcheck = INT_MAX;
        Ns_DStringInit(&ds);
        hPtr = Tcl_FirstHashEntry(&context->poolsTable, &search);
        while (hPtr != NULL) {
            poolPtr = Tcl_GetHashValue(hPtr);
            if (tcheck > poolPtr->maxidle) {
                tcheck = (int)poolPtr->maxidle;
            }
            Ns_Log(Debug, "nsldap: adding pool %s to the list of allowed pools", poolPtr->name);
            Ns_DStringNAppend(&ds, poolPtr->name, (int)(strlen(poolPtr->name) + 1));
            hPtr = Tcl_NextHashEntry(&search);
        }
        context->allowedPools = ns_malloc((size_t)(ds.length + 1));
        memcpy(context->allowedPools, ds.string, ds.length + 1);
        Ns_DStringFree(&ds);
        Ns_TclRegisterTrace(hServer, LDAPInterpInit, context, NS_TCL_TRACE_CREATE);

        if (tcheck > 0) {
            Ns_Log(Debug, "nsldap: Registering LDAPCheckPools (%d)", tcheck);
            Ns_ScheduleProc(LDAPCheckPools, context, 1, tcheck);
        }
    }
    /*
     * Register ReleaseLDAP to run after each connection to return
     * handle not released by the thread. This is for situations where
     * the script aborts or the programmer forgets to call
     * releasehandle
     */
    Ns_RegisterServerTrace(hServer, ReleaseLDAP, context);

    Ns_Log(Notice, "nsldap: version %s loaded", NSLDAP_VERSION);

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * LDAPCreatePool --
 *
 *	Create a new pool.
 *
 * Results:
 *	Pointer to newly allocated Pool structure.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static Pool  *
LDAPCreatePool(const char *pool, const char *path)
{
    Pool            *poolPtr;
    Handle          *handlePtr;
    int              i;
    const char      *host;

    host = Ns_ConfigGetValue(path, CONFIG_HOST);
    if (host == NULL) {
        Ns_Log(Error, "nsldap: required host missing for pool '%s'",
               pool);
        return NULL;
    }
    poolPtr = ns_malloc(sizeof(Pool));
    Ns_MutexInit(&poolPtr->lock);
    Ns_MutexSetName2(&poolPtr->lock, "nsldap", pool);
    Ns_CondInit(&poolPtr->waitCond);
    Ns_CondInit(&poolPtr->getCond);
    poolPtr->host = host;
    if (Ns_ConfigGetInt(path, "port", &poolPtr->port) == NS_FALSE) {
        poolPtr->port = LDAP_PORT;
    }
    poolPtr->name = pool;
    poolPtr->waiting = 0;
    poolPtr->user = Ns_ConfigGetValue(path, CONFIG_USER);
    poolPtr->pass = Ns_ConfigGetValue(path, CONFIG_PASS);
    poolPtr->desc = Ns_ConfigGetValue("ns/db/pools", pool);
    poolPtr->stale_on_close = 0;
    if (Ns_ConfigGetBool(path, CONFIG_VERBOSE,
                         &poolPtr->fVerbose) == NS_FALSE) {
        poolPtr->fVerbose = NS_FALSE;
    }
    if (Ns_ConfigGetInt(path, CONFIG_CONNS, &poolPtr->nhandles) == NS_FALSE ||
        poolPtr->nhandles <= 0) {

        poolPtr->nhandles = 2;
    }
    if (Ns_ConfigGetInt(path, "MaxIdle", &i) == NS_FALSE || i < 0) {
        i = 600;                    /* 10 minutes */
    }
    poolPtr->maxidle = i;
    if (Ns_ConfigGetInt(path, "MaxOpen", &i) == NS_FALSE || i < 0) {
        i = 3600;                   /* 1 hour */
    }
    poolPtr->maxopen = i;
    poolPtr->firstPtr = poolPtr->lastPtr = NULL;
    for (i = 0; i < poolPtr->nhandles; ++i) {
        handlePtr = ns_malloc(sizeof(Handle));
        Ns_DStringInit(&handlePtr->ErrorMsg);
        handlePtr->poolPtr = poolPtr;
        handlePtr->connected = NS_FALSE;
        handlePtr->otime = handlePtr->atime = 0;
        handlePtr->stale = NS_FALSE;
        handlePtr->stale_on_close = 0;

        /*
         * The following elements of the Handle structure could be
         * obtained by dereferencing the poolPtr.  They're only needed
         * to maintain the original Handle structure definition which
         * was designed to allow handles outside of pools, a feature
         * no longer supported.
         */

        handlePtr->host = poolPtr->host;
        handlePtr->port = poolPtr->port;
        handlePtr->user = poolPtr->user;
        handlePtr->password = poolPtr->pass;
        handlePtr->verbose = poolPtr->fVerbose;
        handlePtr->poolname = pool;
        LDAPReturnHandle(handlePtr);
    }

    return poolPtr;
}

/*
 *----------------------------------------------------------------------
 *
 * LDAPReturnHandle --
 *
 *	Return a handle to its pool.  Connected handles are pushed on
 *	the front of the list, disconnected handles are appended to
 *	the end.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Handle is returned to the pool.  Note:  The pool lock must be
 *	held by the caller and this function does not signal a thread
 *	waiting for handles.
 *
 *----------------------------------------------------------------------
 */

static void
LDAPReturnHandle(Handle *handlePtr)
{
    Pool         *poolPtr;

    poolPtr = handlePtr->poolPtr;
    if (poolPtr->firstPtr == NULL) {
        poolPtr->firstPtr = poolPtr->lastPtr = handlePtr;
        handlePtr->nextPtr = NULL;
    } else if (handlePtr->connected) {
        handlePtr->nextPtr = poolPtr->firstPtr;
        poolPtr->firstPtr = handlePtr;
    } else {
        poolPtr->lastPtr->nextPtr = handlePtr;
        poolPtr->lastPtr = handlePtr;
        handlePtr->nextPtr = NULL;
    }
}



/*
 *----------------------------------------------------------------------
 *
 * LDAPCheckPools --
 *
 *	Schedule procedure to check all pools.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static void
LDAPCheckPools(void *ctx, int UNUSED(id))
{
    Tcl_HashEntry *hPtr;
    Tcl_HashSearch search;
    Pool *poolPtr;
    Context *context;

    context = (Context *) ctx;
    hPtr = Tcl_FirstHashEntry(&context->poolsTable, &search);
    while (hPtr != NULL) {
        poolPtr = Tcl_GetHashValue(hPtr);
        LDAPCheckPool(poolPtr);
        hPtr = Tcl_NextHashEntry(&search);
    }
}


/*
 *----------------------------------------------------------------------
 *
 * LDAPCheckPool --
 *
 *	Verify all handles in a pool are not stale.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Stale handles, if any, are closed.
 *
 *----------------------------------------------------------------------
 */

static void
LDAPCheckPool(Pool *poolPtr)
{
    Handle       *handlePtr, *nextPtr;
    Handle       *checkedPtr;
    time_t        now;

    time(&now);
    checkedPtr = NULL;

    /*
     * Grab the entire list of handles from the pool.
     */

    Ns_MutexLock(&poolPtr->lock);
    handlePtr = poolPtr->firstPtr;
    poolPtr->firstPtr = poolPtr->lastPtr = NULL;
    Ns_MutexUnlock(&poolPtr->lock);

    /*
     * Run through the list of handles, closing any which have gone
     * stale, and then return them all to the pool.
     */

    if (handlePtr != NULL) {
        while (handlePtr != NULL) {
            nextPtr = handlePtr->nextPtr;
            if (LDAPIsStale(handlePtr, now)) {
                LDAPDisconnect(handlePtr);
            }
            handlePtr->nextPtr = checkedPtr;
            checkedPtr = handlePtr;
            handlePtr = nextPtr;
        }

        Ns_MutexLock(&poolPtr->lock);
        handlePtr = checkedPtr;
        while (handlePtr != NULL) {
            nextPtr = handlePtr->nextPtr;
            LDAPReturnHandle(handlePtr);
            handlePtr = nextPtr;
        }
        if (poolPtr->waiting) {
            Ns_CondSignal(&poolPtr->getCond);
        }
        Ns_MutexUnlock(&poolPtr->lock);
    }
}

/*
 *----------------------------------------------------------------------
 *
 * LDAPDisconnect --
 *
 *	Disconnect a handle by closing the LDAP connection if needed.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

void
LDAPDisconnect(Handle *handle)
{
    ldap_unbind_ext(handle->ldaph, NULL, NULL);
    handle->connected = NS_FALSE;
    handle->atime = handle->otime = 0;
    handle->stale = NS_FALSE;
}


/*
 *----------------------------------------------------------------------
 *
 * LDAPConnect --
 *
 *	Connect a handle by opening the connection to the LDAP server.
 *      and Binding as the specified user/password (or anonymously)
 *
 * Results:
 *	NS_OK if connect ok, NS_ERROR otherwise.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static int
LDAPConnect(Handle *handlePtr)
{
    int           err;
    Tcl_DString   ds;
    struct berval cred;

    Tcl_DStringInit(&ds);
    Ns_DStringPrintf(&ds, "ldap://%s:%d", handlePtr->host, handlePtr->port );

    err = ldap_initialize(&handlePtr->ldaph, ds.string);
    Tcl_DStringFree(&ds);

    if (err != LDAP_SUCCESS) {
        Ns_Log(Error, "nsldap: could not open connection to server %s on port %d: %s",
               handlePtr->host, handlePtr->port, strerror(errno));
        handlePtr->connected = NS_FALSE;
        handlePtr->atime = handlePtr->otime = 0;
        handlePtr->stale = NS_FALSE;
        return NS_ERROR;
    }
#ifdef LDAPV3
    {
        int version = LDAP_VERSION3;
        if (ldap_set_option(handlePtr->ldaph, LDAP_OPT_PROTOCOL_VERSION, &version) != LDAP_SUCCESS) {
            Ns_Log(Error, "nsldap: could not set protocol version to LDAPV3");
            handlePtr->connected = NS_FALSE;
            handlePtr->atime = handlePtr->otime = 0;
            handlePtr->stale = NS_FALSE;
            return NS_ERROR;
        }
    }
#endif

    cred.bv_val = (char *)handlePtr->password;
    cred.bv_len = strlen(handlePtr->password);
    err = ldap_sasl_bind_s(handlePtr->ldaph, handlePtr->user, LDAP_SASL_SIMPLE, &cred,
                           NULL, NULL,     /* no controls right now */
                           NULL);         /* we don't care about the server's credentials */
    if (err != LDAP_SUCCESS) {
        Ns_Log(Error, "nsldap: could not bind to server %s: %s",
               handlePtr->host, ldap_err2string(err));
        return NS_ERROR;
    }
    handlePtr->connected = NS_TRUE;
    handlePtr->atime = handlePtr->otime = time(NULL);
    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * LDAPIsStale --
 *
 *	Check to see if a handle is stale.
 *
 * Results:
 *	NS_TRUE if handle stale, NS_FALSE otherwise.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static int
LDAPIsStale(Handle *handlePtr, time_t now)
{
    time_t    minAccess, minOpen;

    if (handlePtr->connected) {
        minAccess = now - handlePtr->poolPtr->maxidle;
        minOpen = now - handlePtr->poolPtr->maxopen;
        if ((handlePtr->poolPtr->maxidle && handlePtr->atime < minAccess) ||
            (handlePtr->poolPtr->maxopen && (handlePtr->otime < minOpen)) ||
            (handlePtr->stale == NS_TRUE) ||
            (handlePtr->poolPtr->stale_on_close > handlePtr->stale_on_close)) {

            if (handlePtr->poolPtr->fVerbose) {
                Ns_Log(Notice, "nsldap: closing %s handle in pool '%s'",
                       handlePtr->atime < minAccess ? "idle" : "old",
                       handlePtr->poolname);
            }
            return NS_TRUE;
        }
    }

    return NS_FALSE;
}


/*
 *----------------------------------------------------------------------
 *
 * LDAPPoolTimedGetMultipleHandles --
 *
 *	Return 1 or more handles from a pool within the given number
 *	of seconds.
 *
 * Results:
 *	NS_OK if the handlers where allocated, NS_TIMEOUT if the
 *	thread could not wait long enough for the handles, NS_ERROR
 *	otherwise.
 *
 * Side effects:
 *	Given array of handles is updated with pointers to allocated
 *	handles.  Also, a connection to the LDAP server may be opened
 *      if needed.
 *
 *----------------------------------------------------------------------
 */

int
LDAPPoolTimedGetMultipleHandles(Handle **handles, const char *pool,
                                int nwant, int wait, Context *context)
{
    Handle    *handlePtr;
    Handle   **handlesPtrPtr = handles;
    Pool      *poolPtr;
    Ns_Time    timeoutStruct, *timePtr;
    int        i, ngot, status;

    /*
     * Verify the pool, the number of available handles in the pool,
     * and that the calling thread does not already own handles from
     * this pool.
     */

    poolPtr = LDAPGetPool(pool, context);
    if (poolPtr == NULL) {
        Ns_Log(Error, "nsldap: no such pool '%s'", pool);
        return NS_ERROR;
    }
    if (poolPtr->nhandles < nwant) {
        Ns_Log(Error, "nsldap: "
               "failed to get %d handles from an ldap pool of only %d handles: '%s'",
               nwant, poolPtr->nhandles, pool);
        return NS_ERROR;
    }
    ngot = LDAPIncrCount(poolPtr, nwant);
    if (ngot > 0) {
        Ns_Log(Error, "nsldap: ldap handle limit exceeded: "
               "thread already owns %d handle%s from pool '%s'",
               ngot, ngot == 1 ? "" : "s", pool);
        LDAPIncrCount(poolPtr, -nwant);
        return NS_ERROR;
    }

    /*
     * Wait until this thread can be the exclusive thread aquireing
     * handles and then wait until all requested handles are available,
     * watching for timeout in either of these waits.
     */

    if (wait <= 0) {
        timePtr = NULL;
    } else {
        Ns_GetTime(&timeoutStruct);
        Ns_IncrTime(&timeoutStruct, wait, 0);
        timePtr = &timeoutStruct;
    }
    status = NS_OK;
    Ns_MutexLock(&poolPtr->lock);
    while (status == NS_OK && poolPtr->waiting) {
        status = Ns_CondTimedWait(&poolPtr->waitCond, &poolPtr->lock, timePtr);
    }
    if (status == NS_OK) {
        poolPtr->waiting = 1;
        while (status == NS_OK && ngot < nwant) {
            while (status == NS_OK && poolPtr->firstPtr == NULL) {
                status = Ns_CondTimedWait(&poolPtr->getCond, &poolPtr->lock,
                                          timePtr);
            }
            /*
             * we obtain a handle from the pool of handles
             */
            if (poolPtr->firstPtr != NULL) {
                handlePtr = poolPtr->firstPtr;
                poolPtr->firstPtr = handlePtr->nextPtr;
                handlePtr->nextPtr = NULL;
                if (poolPtr->lastPtr == handlePtr) {
                    poolPtr->lastPtr = NULL;
                }
                /*
                 * we mark this handle as used by a particular thread
                 */
                handlePtr->ThreadId = Ns_ThreadId();
                Ns_Log(Debug, "nsldap: getting a handle for thread %p", (void*)handlePtr->ThreadId);
                handlesPtrPtr[ngot++] = handlePtr;
            }
        }
        poolPtr->waiting = 0;
        Ns_CondSignal(&poolPtr->waitCond);
    }
    Ns_MutexUnlock(&poolPtr->lock);

    /*
     * Handle special race condition where the final requested handle
     * arrived just as the condition wait was timing out.
     */

    if (status == NS_TIMEOUT && ngot == nwant) {
        status = NS_OK;
    }

    /*
     * If status is still ok, connect any handles not already connected,
     * otherwise return any allocated handles back to the pool, then
     * update the final number of handles owned by this thread.
     */

    for (i = 0; status == NS_OK && i < ngot; ++i) {
        handlePtr = handlesPtrPtr[i];
        if (handlePtr->connected == NS_FALSE) {
            Ns_Log(Debug, "nsldap: connecting handle from pool %s", poolPtr->name);
            status = LDAPConnect(handlePtr);
        }
    }
    if (status != NS_OK) {
        Ns_MutexLock(&poolPtr->lock);
        while (ngot > 0) {
            LDAPReturnHandle(handlesPtrPtr[--ngot]);
        }
        if (poolPtr->waiting) {
            Ns_CondSignal(&poolPtr->getCond);
        }
        Ns_MutexUnlock(&poolPtr->lock);
        LDAPIncrCount(poolPtr, -nwant);
    }
    return status;
}

/*
 *----------------------------------------------------------------------
 *
 * LDAPBouncePool --
 *
 *	Close all handles in the pool.
 *
 * Results:
 *	NS_OK if pool was bounce, NS_ERROR otherwise.
 *
 * Side effects:
 *	Handles are all marked stale and then closed by CheckPool.
 *
 *----------------------------------------------------------------------
 */

int
LDAPBouncePool(const char *pool, Context *context)
{
    Pool	*poolPtr;
    Handle	*handlePtr;


    poolPtr = LDAPGetPool(pool, context);
    if (poolPtr == NULL) {
        return NS_ERROR;
    }
    Ns_MutexLock(&poolPtr->lock);
    poolPtr->stale_on_close++;
    handlePtr = poolPtr->firstPtr;
    while (handlePtr != NULL) {
        if (handlePtr->connected) {
            handlePtr->stale = 1;
        }
        handlePtr->stale_on_close = poolPtr->stale_on_close;
        handlePtr = handlePtr->nextPtr;
    }
    Ns_MutexUnlock(&poolPtr->lock);
    LDAPCheckPool(poolPtr);

    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * LDAPGetPool --
 *
 *	Return the Pool structure for the given pool name.
 *
 * Results:
 *	Pointer to Pool structure or NULL if pool does not exist.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static Pool *
LDAPGetPool(const char *pool, Context *context)
{
    Tcl_HashEntry   *hPtr;

    hPtr = Tcl_FindHashEntry(&context->poolsTable, pool);
    if (hPtr == NULL) {
        return NULL;
    }

    return (Pool *) Tcl_GetHashValue(hPtr);
}


/*
 *----------------------------------------------------------------------
 *
 * LDAPIncrCount --
 *
 *	Update per-thread count of allocated handles.
 *
 * Results:
 *	Previous count of allocated handles.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static int
LDAPIncrCount(Pool *poolPtr, int incr)
{
    Tcl_HashTable *tablePtr;
    Tcl_HashEntry *hPtr;
    static volatile int initialized = 0;
    static Ns_Tls tls;
    int prev, count, new;

    if (!initialized) {
        Ns_MasterLock();
        if (!initialized) {
            Ns_TlsAlloc(&tls, LDAPFreeCounts);
            initialized = 1;
        }
        Ns_MasterUnlock();
    }
    tablePtr = Ns_TlsGet(&tls);
    if (tablePtr == NULL) {
        tablePtr = ns_malloc(sizeof(Tcl_HashTable));
        Tcl_InitHashTable(tablePtr, TCL_ONE_WORD_KEYS);
        Ns_TlsSet(&tls, tablePtr);
    }
    hPtr = Tcl_CreateHashEntry(tablePtr, (char *) poolPtr, &new);
    if (new) {
        prev = 0;
    } else {
        prev = (int) Tcl_GetHashValue(hPtr);
    }
    count = prev + incr;
    if (count == 0) {
        Tcl_DeleteHashEntry(hPtr);
    } else {
        Tcl_SetHashValue(hPtr, (ClientData) INT2PTR(count));
    }
    return prev;
}


/*
 *----------------------------------------------------------------------
 *
 * LDAPFreeCounts --
 *
 *	TLS cleanup to delete per-thread handle counts table.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static void
LDAPFreeCounts(void *arg) {
    Tcl_HashTable *tablePtr = arg;

    Tcl_DeleteHashTable(tablePtr);
    ns_free(tablePtr);
}

/*
 *----------------------------------------------------------------------
 *
 * LDAPPoolAllowable --
 *
 *	Check that access is allowed to a pool.
 *
 * Results:
 *	NS_TRUE if allowed, NS_FALSE otherwise.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

int
LDAPPoolAllowable(Context *context, const char *pool)
{
    register const char *p;

    p = context->allowedPools;
    if (p != NULL) {
        while (*p != '\0') {
            if (STREQ(pool, p)) {
                return NS_TRUE;
            }
            p = p + strlen(p) + 1;
        }
    }
    return NS_FALSE;
}


/*
 *----------------------------------------------------------------------
 * LDAPEnterHandle --
 *
 *      Enter an LDAP handle and create its handle id.
 *
 * Results:
 *      The LDAP handle id is returned as a Tcl result.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static void
LDAPEnterHandle(Tcl_Interp *interp, Handle *handle, Context *context)
{
    Tcl_HashTable *tablePtr;
    Tcl_HashEntry *he;
    int            new, next;
    char           buf[100];

    tablePtr = &context->activeHandles;
    next = tablePtr->numEntries;
    do {
        sprintf(buf, "nsldap%x", next++);
        he = Tcl_CreateHashEntry(tablePtr, buf, &new);
    } while (!new);
    Tcl_SetResult(interp, buf, TCL_VOLATILE);
    Tcl_SetHashValue(he, handle);
    Ns_Log(Debug, "nsldap: entering handle %s to activeHandles", buf);
}


/*
 *----------------------------------------------------------------------
 * ReleaseLDAP --
 *
 *      Returns handles not freed by the thread to the pool of available
 *      handles. This happens when the programmer doesn't call releasehandle
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static void
ReleaseLDAP(void *context, Ns_Conn *UNUSED(conn))
{
    Context       *ctx;
    Tcl_HashTable *tablePtr;
    Tcl_HashSearch search;
    Tcl_HashEntry *hPtr;
    Handle        *handle;
    const char    *handleName;
    uintptr_t      ThisThreadId;

    ctx = (Context *) context;
    tablePtr = &ctx->activeHandles;
    ThisThreadId = Ns_ThreadId();
    hPtr = Tcl_FirstHashEntry(tablePtr, &search);
    while (hPtr != NULL) {
        handle = Tcl_GetHashValue(hPtr);
        if (ThisThreadId == handle->ThreadId) {
            handleName = Tcl_GetHashKey(tablePtr, hPtr);
            Ns_Log(Notice, "nsldap: returning handle %s to pool %s (you should call releasehandle)",
                   handleName, handle->poolname);
            Tcl_DeleteHashEntry(hPtr);
            LDAPPoolPutHandle(handle);
        }
        hPtr = Tcl_NextHashEntry(&search);
    }
}


/*
 *----------------------------------------------------------------------
 *
 * LDAPPoolPutHandle --
 *
 *	Cleanup and then return a handle to its pool.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Handle is flushed, reset, and possibly closed as required.
 *
 *----------------------------------------------------------------------
 */

void
LDAPPoolPutHandle(Handle *handle)
{
    Handle	*handlePtr;
    Pool	*poolPtr;
    time_t       now;

    Ns_Log(Debug, "nsldap: returning handle to pool %s for thread %p",
           handle->poolname, (void*)(Ns_ThreadId()));

    handlePtr = (Handle *) handle;
    poolPtr = handlePtr->poolPtr;

    /*
     * Cleanup the handle.
     */

    Ns_DStringFree(&handle->ErrorMsg);

    /*
     * Close the handle if it's stale, otherwise update
     * the last access time.
     */

    time(&now);
    if (LDAPIsStale(handlePtr, now)) {
        LDAPDisconnect(handle);
    } else {
        handlePtr->atime = now;
    }
    LDAPIncrCount(poolPtr, -1);
    Ns_MutexLock(&poolPtr->lock);
    LDAPReturnHandle(handlePtr);
    if (poolPtr->waiting) {
        Ns_CondSignal(&poolPtr->getCond);
    }
    Ns_MutexUnlock(&poolPtr->lock);
}

/*
 *----------------------------------------------------------------------
 * LDAPGetHandle --
 *
 *      Get LDAP handle from its handle id.
 *
 * Results:
 *      Return TCL_OK if handle is found or TCL_ERROR otherwise.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static int
LDAPGetHandle(Tcl_Interp *interp, const char *handleId, Handle **handle,
              Tcl_HashEntry **hPtrPtr, Context *context)
{
    Tcl_HashEntry  *hPtr;
    Tcl_HashTable  *tablePtr;

    tablePtr = &context->activeHandles;
    hPtr = Tcl_FindHashEntry(tablePtr, handleId);
    if (hPtr == NULL) {
        Tcl_AppendResult(interp, "invalid ldap id:  \"", handleId, "\"",
                         NULL);
        return TCL_ERROR;
    }
    *handle = (Handle *) Tcl_GetHashValue(hPtr);
    if (hPtrPtr != NULL) {
        *hPtrPtr = hPtr;
    }
    return TCL_OK;
}

#if 0
/*
 *----------------------------------------------------------------------
 * LDAPFail --
 *
 *      Common routine that creates ldap failure message.
 *
 * Results:
 *      Return TCL_ERROR and set LDAP failure message as Tcl result.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static int
LDAPFail(Tcl_Interp *interp, Handle *handle, char *cmd)
{
    Tcl_AppendResult(interp, "LDAP operation \"", cmd, "\" failed", NULL);
    if (handle->ErrorMsg.length > 0) {
        Tcl_AppendResult(interp, "(", handle->ErrorMsg.string,
                         ")", NULL);
    }
    return TCL_ERROR;
}
#endif

/*
 *----------------------------------------------------------------------
 *
 * LDAPInterpInit --
 *
 *      Register new commands with the Tcl interpreter.
 *
 * Results:
 *	NS_OK or NS_ERROR
 *
 * Side effects:
 *	A C function is registered with the Tcl interpreter.
 *
 *----------------------------------------------------------------------
 */

static int
LDAPInterpInit(Tcl_Interp *interp, const void *context)
{

    Tcl_CreateCommand(interp, "ns_ldap", LDAPCmd, (ClientData)context, NULL);

    return NS_OK;
}


/*
 *----------------------------------------------------------------------
 * BadArgs --
 *
 *      Common routine that creates bad arguments message.
 *
 * Results:
 *      Return TCL_ERROR and set bad argument message as Tcl result.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static int
BadArgs(Tcl_Interp *interp, const char **argv, const char *args)
{
    Tcl_AppendResult(interp, "wrong # args: should be \"",
                     argv[0], " ", argv[1], NULL);
    if (args != NULL) {
        Tcl_AppendResult(interp, " ", args, NULL);
    }
    Tcl_AppendResult(interp, "\"", NULL);

    return TCL_ERROR;
}

/*
 *----------------------------------------------------------------------
 * Entry2List --
 *
 *      Convert an LDAP Result to a Tcl List
 *
 * Results:
 *      Returns a Tcl List containing the results
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */


static Tcl_Obj *
Entry2List(Tcl_Interp *interp, LDAP *ld, LDAPMessage *e,
           int attrsonly, int namesonly)
{
    BerElement	*ber;
    Tcl_Obj		*listPtr, *subListPtr;
    char		*dn = NULL, *attr;
    int              i;


    dn = ldap_get_dn( ld, e );
    if (namesonly) {
        if (dn != NULL) {
            listPtr = Tcl_NewStringObj( dn, -1);
            ldap_memfree(dn);
            return listPtr;
        } else {
            return Tcl_NewStringObj("",-1);
        }
    }
    listPtr = Tcl_NewListObj(0, (Tcl_Obj **) NULL);
    if (dn != NULL) {
        if (!attrsonly) {
            Tcl_ListObjAppendElement(interp, listPtr,
                                     Tcl_NewStringObj( "dn", -1));
        }
        Tcl_ListObjAppendElement(interp, listPtr,
                                 Tcl_NewStringObj( dn, -1));
        ldap_memfree( dn );
    }
    for ( attr = ldap_first_attribute( ld, e, &ber );
          attr != NULL; attr = ldap_next_attribute( ld, e, ber ) ) {
        struct berval **bvals;

        Tcl_ListObjAppendElement(interp, listPtr,
                                 Tcl_NewStringObj( attr, -1));
        if (attrsonly) {
            ldap_memfree( attr );
            continue;
        }
        /* each attribute in LDAP can have a list of values */
        subListPtr = Tcl_NewListObj(0, (Tcl_Obj **) NULL);
        bvals = ldap_get_values_len( ld, e, attr);
        if ( bvals != NULL ) {
            for ( i = 0; bvals[i] != NULL; i++ ) {
                Tcl_ListObjAppendElement(interp, subListPtr,
                                         Tcl_NewStringObj( bvals[i]->bv_val,
                                                           (int)(bvals[i]->bv_len)));
            }
            ldap_value_free_len( bvals );
        }
        Tcl_ListObjAppendElement(interp, listPtr, subListPtr);
        ldap_memfree( attr );
    }
    if ( ber != NULL ) {
        ber_free( ber, 0 );
    }
    return listPtr;
}


/*
 *----------------------------------------------------------------------
 *
 * LDAPCmd --
 *
 *      A Tcl command that prints a friendly string with the name
 *      passed in on the first argument.
 *
 * Results:
 *	NS_OK or NS_ERROR;
 *
 * Side effects:
 *	Tcl result is set to a string value.
 *
 *----------------------------------------------------------------------
 */

static int
LDAPCmd(ClientData ctx, Tcl_Interp *interp, int argc, const char **argv)
{

    Handle *handlePtr;
    const char *cmd;
    const char *pool;
    Context *context;

    context = (Context *) ctx;

    if (argc < 2) {
        Tcl_AppendResult(interp, "wrong # of args: should be \"",
                         argv[0], " command ?args ...?", NULL);
        return TCL_ERROR;
    }

    cmd = argv[1];

    if (STREQ(cmd, "open") || STREQ(cmd, "close")) {
        Tcl_AppendResult(interp, "unsupported ns_ldap command: ", cmd, NULL);
        return TCL_ERROR;
    } else if (STREQ(cmd, "pools")) {

        if (argc != 2) {
            return BadArgs(interp, argv, NULL);
        }

        pool = context->allowedPools;
        if (pool != NULL) {
            while (*pool != '\0') {
                Tcl_AppendElement(interp, pool);
                pool = pool + strlen(pool) + 1;
            }
        }
    } else if (STREQ(cmd, "bouncepool")) {

        if (argc != 3) {
            return BadArgs(interp, argv, "pool");
        }
        if (LDAPBouncePool(argv[2], context) == NS_ERROR) {
            Tcl_AppendResult(interp, "could not bounce: ", argv[2], NULL);
            return TCL_ERROR;
        }
    } else if (STREQ(cmd, "gethandle")) {
        int timeoutSecs, nhandles, result;
        Handle **handlesPtrPtr;

        timeoutSecs = 0;
        if (argc >= 4) {
            if (STREQ(argv[2], "-timeout")) {
                if (Tcl_GetInt(interp, argv[3], &timeoutSecs) != TCL_OK) {
                    return TCL_ERROR;
                }
                argv += 2;
                argc -= 2;
            } else if (argc > 4) {
                return BadArgs(interp, argv,
                               "?-timeout timeout? ?pool? ?nhandles?");
            }
        }
        argv += 2;
        argc -= 2;

        /*
         * Determine the pool and requested number of handles
         * from the remaining args.
         */

        pool = argv[0];
        if (pool == NULL) {
            pool = context->defaultPool;
            if (pool == NULL) {
                Tcl_SetObjResult(interp, Tcl_NewStringObj("no defaultpool configured", -1));
                return TCL_ERROR;
            }
        }
        if (LDAPPoolAllowable(context, pool) == NS_FALSE) {
            Tcl_AppendResult(interp, "no access to pool: \"", pool, "\"",
                             NULL);
            return TCL_ERROR;
        }
        if (argc < 2) {
            nhandles = 1;
        } else {
            if (Tcl_GetInt(interp, argv[1], &nhandles) != TCL_OK) {
                return TCL_ERROR;
            }
            if (nhandles <= 0) {
                Tcl_AppendResult(interp, "invalid nhandles \"", argv[1],
                                 "\": should be greater than 0.", NULL);
                return TCL_ERROR;
            }
        }

        /*
         * Allocate handles and enter them into Tcl.
         */

        if (nhandles == 1) {
            handlesPtrPtr = &handlePtr;
        } else {
            handlesPtrPtr = ns_malloc((size_t)nhandles * sizeof(Handle *));
        }
        result = LDAPPoolTimedGetMultipleHandles(handlesPtrPtr, pool,
                                                 nhandles, timeoutSecs, context);
        if (result == NS_OK) {
            Tcl_DString ds;
            int i;

            Tcl_DStringInit(&ds);
            for (i = 0; i < nhandles; ++i) {
                LDAPEnterHandle(interp, handlesPtrPtr[i], context);
                Tcl_DStringAppendElement(&ds, Tcl_GetStringResult(interp));
            }
            Tcl_DStringResult(interp, &ds);
        }
        if (handlesPtrPtr != &handlePtr) {
            ns_free(handlesPtrPtr);
        }
        if (result != NS_TIMEOUT && result != NS_OK) {
            Tcl_AppendResult(interp, "could not allocate ",
                             nhandles > 1 ? argv[1] : "1", " handle",
                             nhandles > 1 ? "s" : "", " from pool \"",
                             pool, "\"", NULL);
            return TCL_ERROR;
        }

    } else {
        Tcl_HashEntry  *hPtr;

        /*
         * All remaining commands require a valid ldap handle
         */

        if (argc < 3) {
            return BadArgs(interp, argv, "ldapId ?args?");
        }
        if (LDAPGetHandle(interp, argv[2], &handlePtr, &hPtr, context) != TCL_OK) {
            return TCL_ERROR;
        }
        Ns_DStringFree(&handlePtr->ErrorMsg);

        /*
         * the following commands require just the handle.
         */

        if (STREQ(cmd, "poolname") ||
            STREQ(cmd, "password") ||
            STREQ(cmd, "user") ||
            STREQ(cmd, "host") ||
            STREQ(cmd, "disconnect") ||
            STREQ(cmd, "releasehandle") ||
            STREQ(cmd, "connected")) {

            if (argc != 3) {
                return BadArgs(interp, argv, "ldapId");
            }

            if (STREQ(cmd, "poolname")) {
                Tcl_SetObjResult(interp, Tcl_NewStringObj(handlePtr->poolname, -1));
            } else if (STREQ(cmd, "password")) {
                Tcl_SetObjResult(interp,  Tcl_NewStringObj(handlePtr->password, -1));
            } else if (STREQ(cmd, "user")) {
                Tcl_SetObjResult(interp, Tcl_NewStringObj(handlePtr->user, -1));
            } else if (STREQ(cmd, "host")) {
                Tcl_SetObjResult(interp, Tcl_NewStringObj(handlePtr->host, -1));
            } else if (STREQ(cmd, "disconnect")) {
                LDAPDisconnect(handlePtr);
            } else if (STREQ(cmd, "releasehandle")) {
                Ns_Log(Debug, "nsldap: releasehandle %s", argv[2]);
                Tcl_DeleteHashEntry(hPtr);
                LDAPPoolPutHandle(handlePtr);
            } else if (STREQ(cmd, "connected")) {
                sprintf(Tcl_GetStringResult(interp), "%d", handlePtr->connected);
            }

        } else if (STREQ(cmd, "add")) {
            /*
             * this command requires more than 6 arguments and
             * they must come in pairs. It's intended use is
             * ns_ldap add $lh dn attribute value attribute value ...
             */
            LDAPMod *mod, **moda;
            const char *dn = NULL;
            int  i, ret = TCL_OK;
            int  lrc; /* ldap result code */

            if (argc < 6 || (argc % 2) == 1) {
                return BadArgs(interp, argv, "ldapId dn ?attr value?");
            }

            dn = argv[3];

            mod = (LDAPMod *)ns_malloc( (size_t)((argc - 4)/2 + 1) * sizeof(LDAPMod));
            moda = (LDAPMod **)ns_malloc( (size_t)((argc - 4)/2 + 1) * sizeof(LDAPMod*));

            for (i = 0; i < (argc - 4)/2; i++) {
                const char *attr, *val;
                int  vlen;

                attr = argv[2*i + 4];
                val = argv[2*i + 5];

                mod[i].mod_op = LDAP_MOD_ADD;
                mod[i].mod_type = (char *)attr;
                if (Tcl_SplitList(interp, val, &vlen, (const char***)&mod[i].mod_values) != TCL_OK) {
                    int j;

                    Tcl_AppendResult(interp, "nsldap [", argv[1], "]: ",
                                     Tcl_GetStringResult(interp), NULL);
                    for(j = 0; j < i; j++) {
                        Tcl_Free( (char *)moda[j]->mod_values);
                    }
                    ns_free(mod);
                    ns_free(moda);
                    return TCL_ERROR;
                }

                moda[i] = &mod[i];
            }

            moda[i] = NULL;

            lrc = ldap_add_ext_s(handlePtr->ldaph, dn, moda, NULL, NULL);
            if ( lrc != LDAP_SUCCESS) {
                Ns_Log(Notice, "nsldap: ldap_add_s failed (%d)", lrc);
                Tcl_AppendResult(interp, "nsldap [", argv[1], "]: ",
                                 ldap_err2string( lrc ),
                                 NULL);
                ret = TCL_ERROR;
            }

            for(i = 0; moda[i]; i++) {
                Tcl_Free( (char *)moda[i]->mod_values);
            }
            ns_free(mod);
            ns_free(moda);
            return ret;

        } else if (STREQ(cmd, "compare")) {
            const  char   *dn, *attr, *value;
            struct berval  bvalue;
            int            lrc;

            if (argc != 6) {
                return BadArgs(interp, argv, "ldapId dn attr value");
            }

            dn = argv[3];
            attr = argv[4];
            value = argv[5];

            bvalue.bv_val = (char *)argv[5];
            bvalue.bv_len = strlen(bvalue.bv_val);

            lrc = ldap_compare_ext_s(handlePtr->ldaph, dn, attr, &bvalue, NULL, NULL);
            if (lrc == LDAP_COMPARE_TRUE) {
                Tcl_SetObjResult(interp, Tcl_NewIntObj(0));
                return TCL_OK;
            } else if (lrc == LDAP_COMPARE_FALSE) {
                Tcl_SetObjResult(interp, Tcl_NewIntObj(0));
                return TCL_OK;
            } else {
                Tcl_AppendResult(interp, "nsldap [", argv[1], "]: ",
                                 ldap_err2string(lrc), NULL);
                return TCL_ERROR;
            }
        } else if (STREQ(cmd, "delete")) {
            const char *dn;
            int         lrc;

            if (argc != 4) {
                return BadArgs(interp, argv, "ldapId dn");
            }

            dn = argv[3];

            lrc = ldap_delete_ext_s(handlePtr->ldaph, dn, NULL, NULL);

            if (lrc != LDAP_SUCCESS) {
                Tcl_AppendResult(interp, "nsldap [", argv[1], "]: ",
                                 ldap_err2string(lrc), NULL);
                return TCL_ERROR;
            }

            return TCL_OK;
        } else if (STREQ(cmd, "modify")) {
            /*
             * ns_ldap modify $lh $dn
             *                     ?add: fld valList ...?
             *                     ?mod: fld valList ...?
             *                     ?del: fld valList ...?
             */
            LDAPMod    *mod, **moda;
            const char *dn;
            int         i, lrc, mode, count, ret = TCL_OK;

            if (argc < 7) {
            mod_err:
                return BadArgs(interp, argv, "ldapId dn ?add: fld vals ...? ?mod: fld vals ...? ?del: fld vals ...?");
            }

            dn = argv[3];

            /*
             * validate arguments, and count number of discrete changes
             */

            mode = -1;
            for (count = 0, i=4; i < argc; i++) {
                if (STREQ(argv[i], "add:")) {
                    mode = LDAP_MOD_ADD;
                    continue;
                }
                if (STREQ(argv[i], "mod:")) {
                    mode = LDAP_MOD_REPLACE;
                    continue;
                }
                if (STREQ(argv[i], "del:")) {
                    mode = LDAP_MOD_DELETE;
                    continue;
                }
                switch(mode) {
                case LDAP_MOD_ADD:
                case LDAP_MOD_REPLACE:
                    if (argc - i < 2) {
                        goto mod_err;
                    }
                    i++;
                    count++;
                    break;
                case LDAP_MOD_DELETE:
                    count++;
                    break;
                default:
                    goto mod_err;
                }
            }
            if (count == 0) {
                return TCL_OK;
            }

            mod = (LDAPMod *)ns_malloc( (size_t)(count+1) * sizeof(LDAPMod));
            moda = (LDAPMod **)ns_malloc( (size_t)(count+1) * sizeof(LDAPMod*));

            /*
             * Process arguments, and generate the LDAPMod array.
             */

            mode = -1;
            for (count=0,i=4; i < argc; i++) {
                const char  *attr, *val;
                int          vlen;

                if (STREQ(argv[i], "add:")) {
                    mode = LDAP_MOD_ADD;
                    continue;
                }
                if (STREQ(argv[i], "mod:")) {
                    mode = LDAP_MOD_REPLACE;
                    continue;
                }
                if (STREQ(argv[i], "del:")) {
                    mode = LDAP_MOD_DELETE;
                    continue;
                }

                attr = argv[i];

                switch (mode) {
                case LDAP_MOD_ADD:
                case LDAP_MOD_REPLACE:
                    val = argv[i+1];
                    mod[count].mod_op = mode;
                    mod[count].mod_type = (char *)attr;
                    if (Tcl_SplitList(interp, val, &vlen, (const char ***)&mod[count].mod_values) != TCL_OK) {
                        Tcl_AppendResult(interp, "nsldap [", argv[1], "]: ",
                                         Tcl_GetStringResult(interp), NULL);
                        for (i = 0; moda[i]; i++) {
                            if (moda[i]->mod_values != NULL)
                                Tcl_Free( (char *)moda[i]->mod_values);
                        }
                        ns_free(mod);
                        ns_free(moda);

                        return TCL_ERROR;
                    }
                    moda[count] = &mod[count];
                    /* skip val */
                    i++;
                    count++;
                    break;
                case LDAP_MOD_DELETE:
                    mod[count].mod_op = mode;
                    mod[count].mod_type = (char *)attr;
                    mod[count].mod_values = NULL;

                    moda[count] = &mod[count];

                    count++;
                    break;
                }
            }

            moda[count] = NULL;

            lrc = ldap_modify_ext_s(handlePtr->ldaph, dn, moda, NULL, NULL);
            if (lrc != LDAP_SUCCESS) {
                Tcl_AppendResult(interp, "nsldap [", argv[1], "]: ",
                                 ldap_err2string(lrc), NULL);
                ret = TCL_ERROR;
            }
            for (i = 0; moda[i]; i++) {
                if (moda[i]->mod_values != NULL)
                    Tcl_Free( (char *)moda[i]->mod_values);
            }
            ns_free(mod);
            ns_free(moda);

            return ret;
        } else if (STREQ(cmd, "modrdn")) {
            /*
             * nsldap modrdn $lh dn rdn ?deloldrdn?
             */
            const char *dn, *rdn;
            int         lrc, deloldrdn = 0;

            if (argc < 5 || argc > 6) {
                return BadArgs(interp, argv, "ldapId dn rdn ?deloldrdn?");
            }

            dn = argv[3];
            rdn = argv[4];

            if (argc == 6 &&
                Tcl_GetBoolean(interp, argv[5], &deloldrdn) != TCL_OK)
                return TCL_ERROR;

            lrc = ldap_rename_s(handlePtr->ldaph, dn, rdn, NULL, deloldrdn, NULL, NULL);
            if (lrc != LDAP_SUCCESS) {
                Tcl_AppendResult(interp, "nsldap [", argv[1], "]: ",
                                 ldap_err2string( lrc ), NULL);
                return TCL_ERROR;
            }

            return TCL_OK;

        } else if (STREQ(cmd, "bind")) {
            /*
             * nsldap bind $lh username password
             */
            const char   *dn, *pass;
            struct berval berpass;
            struct berval bercred;
            int    err;

            if (argc < 3) {
                return BadArgs(interp, argv, "ldapId <dn:user> password ");
            }

            dn = argv[3];
            pass = argv[4];

            berpass.bv_val = (char *)pass;
            berpass.bv_len = strlen(pass);
            bercred.bv_val = (char *)handlePtr->password;
            bercred.bv_len = strlen(handlePtr->password);

            err = ldap_sasl_bind_s(handlePtr->ldaph, dn, LDAP_SASL_SIMPLE, &berpass,
                                   NULL, NULL,
                                   NULL);

            /*
             * Rebind with original authentication credentials.
             */
            ldap_sasl_bind_s(handlePtr->ldaph, handlePtr->user, LDAP_SASL_SIMPLE, &bercred,
                             NULL, NULL,
                             NULL);

            if (err != LDAP_SUCCESS) {
                Ns_Log(Error, "nsldap: could not bind for %s : %s",
                       dn, ldap_err2string(err));
                Tcl_SetObjResult(interp, Tcl_NewIntObj(0));
                return TCL_ERROR;

            } else {
                Tcl_SetObjResult(interp, Tcl_NewIntObj(1));
                return TCL_OK;
            }
            return TCL_OK;



        } else if (STREQ(cmd, "search")) {
            /*
             * ns_ldap search $lh
             *                ?-scope [base onelevel subtree]?
             *                ?-attrs bool?
             *                ?-names bool?
             *                base
             *                ?filter?
             */
            LDAPMessage   *result, *e;
            const char    *base, *filter, *opt;
            const char   **attrs = NULL;
            int            scope = LDAP_SCOPE_BASE;
            int            attrsonly = 0;
            int            namesonly = 0;
            int            idx, msgid, rc;
            Tcl_Obj       *listPtr;

            for (idx = 3; (argc - idx) > 1; idx += 2) {
                opt = argv[idx];

                if (opt[0] != '-')
                    break;
                if (STREQ(opt, "-scope")) {
                    if (STREQ(argv[idx+1], "base")) {
                        scope = LDAP_SCOPE_BASE;
                    } else if (STREQ(argv[idx+1], "onelevel")) {
                        scope = LDAP_SCOPE_ONELEVEL;
                    } else if (STREQ(argv[idx+1], "subtree")) {
                        scope = LDAP_SCOPE_SUBTREE;
                    } else {
                        Tcl_AppendResult(interp, "nsldap [", argv[1],
                                         "]: unknown scope, must be ",
                                         " [base, onelevel, subtree]",
                                         NULL);
                        return TCL_ERROR;
                    }
                } else if (STREQ(argv[idx], "-attrs")) {
                    if (Tcl_GetBoolean(interp, argv[idx+1], &attrsonly)
                        != TCL_OK)
                        return TCL_ERROR;
                } else if (STREQ(argv[idx], "-names")) {
                    if (Tcl_GetBoolean(interp, argv[idx+1], &namesonly)
                        != TCL_OK)
                        return TCL_ERROR;
                    if (namesonly)
                        attrsonly = 1;
                } else {
                    Tcl_AppendResult(interp, "nsldap [", argv[1], "]: ",
                                     "bad option \"", opt,
                                     "\": must be -attrs, -names or ",
                                     "-scope", NULL);
                    return TCL_ERROR;
                }
            }
            if ( (argc - idx) < 1) {
                return BadArgs(interp, argv, "ldapId ?options? base ?filter? ?attrs ...?");
                return TCL_ERROR;
            }
            base = argv[idx];
            if ( (argc -idx) > 1)
                filter = argv[idx+1];
            else
                filter = "objectClass=*";

            idx += 2;
            if (idx < argc) {
                int j;

                attrs = ns_malloc( (size_t)(argc-idx+1) * sizeof(char *));
                for (j = 0; idx < argc; j++) {
                    attrs[j] = argv[idx++];
                }
                attrs[j] = NULL;
            }
            rc = ldap_search_ext(handlePtr->ldaph, base, scope, filter,
                                 (char **)attrs, attrsonly,
                                 NULL /* serverctrls */, NULL /* clientctrls */,
                                 NULL /*struct timeval *timeout */,
                                 LDAP_NO_LIMIT,
                                 &msgid );
            if (attrs != NULL)
                ns_free( attrs );
            if (rc != LDAP_SUCCESS) {
                /* how do I check the error??? */
                Tcl_AppendResult(interp, "nsldap [", argv[1], "]: ",
                                 "couldn't perform search."
                                 , NULL);
                return TCL_ERROR;
            }

            listPtr = Tcl_NewListObj(0, (Tcl_Obj **) NULL);
            while ( (rc = ldap_result(handlePtr->ldaph, msgid, 0, &timeout, &result)) == LDAP_RES_SEARCH_ENTRY) {
                /*
                 * foreach entry print out name + all attrs and values
                 */

                for (e = ldap_first_entry(handlePtr->ldaph, result);
                     e != NULL; e = ldap_next_entry(handlePtr->ldaph, e)) {
                    Tcl_ListObjAppendElement(interp, listPtr,
                                             Entry2List(interp, handlePtr->ldaph, e, attrsonly, namesonly));
                }
                ldap_msgfree(result);
            }

            /* Must free final result */
            if (rc == -1 || rc == 0) {
                Tcl_DecrRefCount(listPtr);
                if (rc == -1) {
                    int err;
                    char *dn;

                    ldap_parse_result(handlePtr->ldaph, result, &err, &dn, NULL, NULL, NULL, 0);
                    Tcl_AppendResult(interp, "nsldap [", argv[1], "]: ",
                                     "couldn't retrieve search results: ",
                                     ldap_err2string(err),
                                     NULL);
                    ldap_msgfree(result);
                    return TCL_ERROR;
                } else {
                    Tcl_AppendResult(interp, "nsldap [", argv[1], "]: ",
                                     "couldn't retrieve search results:",
                                     " timeout", NULL);
                    ldap_msgfree(result);
                    return TCL_ERROR;
                }
            } else {
                ldap_msgfree(result);
                Tcl_SetObjResult(interp, listPtr);
                return TCL_OK;
            }
        } else {
            Tcl_AppendResult(interp, argv[0], ": Unknown command\"",
                             argv[1], "\": should be "
                             "bind, "
                             "bouncepool, "
                             "connected, "
                             "disconnect, "
                             "gethandle, "
                             "host, "
                             "password, "
                             "poolname, "
                             "releasehandle, "
                             "or user", NULL);
            return TCL_ERROR;
        }
    }
    return TCL_OK;
}

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * fill-column: 78
 * indent-tabs-mode: nil
 * End:
 */
