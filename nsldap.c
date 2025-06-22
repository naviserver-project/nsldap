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

#define NSLDAP_VERSION  "1.0d2"

#define CONFIG_USER     "user"          /* LDAP default bind DN */
#define CONFIG_PASS     "password"      /* DN password */
#define CONFIG_HOST     "host"          /* LDAP server */
#define CONFIG_CONNS    "connections"   /* Number of LDAP connections. */
#define CONFIG_VERBOSE  "verbose"       /* Log LDAP queries and errors */

/*
 * Forward compatibility, in case a new version of the module is compiled
 * against an old version of NaviServer.
 */
#ifndef TCL_SIZE_T
# define TCL_SIZE_T           int
#endif
#ifndef TCL_OBJCMDPROC_T
# define TCL_OBJCMDPROC_T     Tcl_ObjCmdProc
# define TCL_CREATEOBJCOMMAND Tcl_CreateObjCommand
#endif
#ifndef TCL_INDEX_NONE
# define TCL_INDEX_NONE       -1
#endif

/*
 * The Ns_ModuleVersion variable is required.
 */
NS_EXPORT int Ns_ModuleVersion = 1;
NS_EXPORT Ns_ModuleInitProc Ns_ModuleInit;

struct Handle;

typedef struct Pool {
    const char    *name;
    const char    *desc;
    const char    *schema;
    const char    *host;
    const char    *uri;
    const char    *dn;
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
    const char   *schema;
    const char   *host;
    const char   *uri;
    const char   *dn;
    int           port;
    const char   *user;
    const char   *password;
    LDAP         *ldaph;
    LDAPMessage  *ldapmessageh;
    Tcl_DString   ErrorMsg;
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

static void
LDAPEnterHandle(Tcl_Interp *interp, Handle *handle, Context *context);

static Ns_ReturnCode
LDAPBouncePool(const char *pool, Context *context);

static void
LDAPCheckPool(Pool *poolPtr);

static Ns_SchedProc LDAPCheckPools;
static TCL_OBJCMDPROC_T LDAPObjCmd;

static Ns_ReturnCode
LDAPConnect(Handle *handlePtr);

static Pool *
LDAPCreatePool(const char *pool, const char *path);

static void
LDAPDisconnect(Handle *handle);

static void
LDAPFreeCounts(void *arg);

static Pool *
LDAPGetPool(const char *pool, Context *context);

static int
LDAPIncrCount(Pool *poolPtr, int incr);

static Ns_TclTraceProc LDAPInterpInit;

static bool
LDAPIsStale(Handle *handlePtr, time_t now);

static bool
LDAPPoolAllowable(Context *context, const char *pool);

static void
LDAPPoolPutHandle(Handle *handle);

static Ns_ReturnCode
LDAPGetHandle(Tcl_Interp *interp, const char *handleId, Handle **handle,
              Tcl_HashEntry **hPtrPtr, Context *context);

static Ns_ReturnCode
LDAPPoolTimedGetMultipleHandles(Handle **handles, const char *pool,
                                int nwant, int wait, Context *context);
static void
LDAPReturnHandle(Handle *handlePtr);

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

NS_EXPORT Ns_ReturnCode
Ns_ModuleInit(const char *hServer, const char *UNUSED(hModule))
{
    Tcl_HashEntry  *hPtr;
    Tcl_HashSearch  search;
    Pool           *poolPtr;
    Ns_Set         *pools;
    Tcl_DString     ds;
    const char     *pool, *path, *allowed;
    register char  *p;
    int             new, tcheck;
    Context        *context;

    /* Get Memory for the new Context */

    context = ns_malloc(sizeof(Context));

    Tcl_DStringInit(&ds);
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
        Tcl_DStringInit(&ds);
        hPtr = Tcl_FirstHashEntry(&context->poolsTable, &search);
        while (hPtr != NULL) {
            poolPtr = Tcl_GetHashValue(hPtr);
            if (tcheck > poolPtr->maxidle) {
                tcheck = (int)poolPtr->maxidle;
            }
            Ns_Log(Debug, "nsldap: adding pool %s to the list of allowed pools", poolPtr->name);
            Tcl_DStringAppend(&ds, poolPtr->name, (int)(strlen(poolPtr->name) + 1));
            hPtr = Tcl_NextHashEntry(&search);
        }
        context->allowedPools = ns_malloc((size_t)ds.length + 1u);
        memcpy(context->allowedPools, ds.string, (size_t)ds.length + 1u);
        Tcl_DStringFree(&ds);
        Ns_TclRegisterTrace(hServer, LDAPInterpInit, context, NS_TCL_TRACE_CREATE);

        if (tcheck > 0) {
            Ns_Time interval;
            int     rc;

            Ns_Log(Debug, "nsldap: Registering LDAPCheckPools (%d)", tcheck);
            interval.sec = tcheck;
            interval.usec = 0;
            rc = Ns_ScheduleProcEx(LDAPCheckPools, context, NS_SCHED_THREAD, &interval, NULL);
            if (rc == NS_ERROR) {
                return NS_ERROR;
            }
            Ns_Log(Notice, "nsldap: scheduled checkproc has id %d",  rc);
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
    int              i, defaultPort = LDAP_PORT;
    const char      *host, *portString;

    poolPtr = ns_malloc(sizeof(Pool));
    Ns_MutexInit(&poolPtr->lock);
    Ns_MutexSetName2(&poolPtr->lock, "nsldap", pool);
    Ns_CondInit(&poolPtr->waitCond);
    Ns_CondInit(&poolPtr->getCond);

    host = Ns_ConfigGetValue(path, CONFIG_HOST);
    poolPtr->uri = Ns_ConfigGetValue(path, "uri");
    poolPtr->schema = Ns_ConfigGetValue(path, "schema");
    portString = Ns_ConfigGetValue(path, "port");
    poolPtr->user = Ns_ConfigGetValue(path, CONFIG_USER);
    poolPtr->pass = Ns_ConfigGetValue(path, CONFIG_PASS);
    poolPtr->dn = NULL;
    if (poolPtr->uri != NULL) {
        if (poolPtr->schema != NULL || poolPtr->host != NULL || portString != NULL) {
            Ns_Log(Warning, "nsldap: when LDAP URI is used, configuration values of"
                   " schema, host, and port are ignored for pool '%s'", pool);
        } else {
            LDAPURLDesc *parsedURI;
            int rc;

            rc = ldap_url_parse(poolPtr->uri, &parsedURI);
            if (rc != LDAP_SUCCESS) {
                Ns_Log(Error, "nsldap: invalid URI '%s' for pool '%s', ldap_url_parse failed: %s",
                       poolPtr->uri, pool, ldap_err2string(rc));
                return NULL;
            }
            poolPtr->schema = ns_strdup(parsedURI->lud_scheme);
#ifdef OPENLDAP_VERSION
            poolPtr->dn     = ns_strdup(parsedURI->lud_dn);
#endif
            poolPtr->host   = ns_strdup(parsedURI->lud_host);
            poolPtr->port   = parsedURI->lud_port;
            ldap_free_urldesc(parsedURI);
        }
    } else {
        if (host == NULL) {
            Ns_Log(Error, "nsldap: required host missing for pool '%s'",
                   pool);
            return NULL;
        }
        poolPtr->host = host;
        if (poolPtr->schema == NULL) {
            poolPtr->schema = "ldap";
        } else if (strcmp(poolPtr->schema, "ldaps") == 0) {
            defaultPort = LDAPS_PORT;
        }
        if (Ns_ConfigGetInt(path, "port", &poolPtr->port) == NS_FALSE) {
            poolPtr->port = defaultPort;
        }
    }
    poolPtr->name = pool;
    poolPtr->waiting = 0;
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
        Tcl_DStringInit(&handlePtr->ErrorMsg);
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
        handlePtr->uri = poolPtr->uri;
        handlePtr->dn = poolPtr->dn;
        handlePtr->schema = poolPtr->schema;
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

static void
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

static Ns_ReturnCode
LDAPConnect(Handle *handlePtr)
{
    int           rc;
    Tcl_DString   ds;
    struct berval cred;

    if (handlePtr->uri != NULL) {
        Ns_Log(Debug, "nsldap : try to CONNECT new style: <%s>", handlePtr->uri);
        rc = ldap_initialize(&handlePtr->ldaph, handlePtr->uri);
    } else {
        Tcl_DStringInit(&ds);
        Ns_DStringPrintf(&ds, "%s://%s:%d", handlePtr->schema, handlePtr->host, handlePtr->port);
        Ns_Log(Debug, "nsldap: try to CONNECT old style: <%s>", ds.string);
        rc = ldap_initialize(&handlePtr->ldaph, ds.string);
        Tcl_DStringFree(&ds);
    }
    Ns_Log(Debug, "nsldap: CONNECT returned: %s", ldap_err2string(rc));

    if (rc != LDAP_SUCCESS) {
        Ns_Log(Error, "nsldap: could not open connection to server %s://%s on port %d: %s",
               handlePtr->schema, handlePtr->host, handlePtr->port, ldap_err2string(rc));
        handlePtr->connected = NS_FALSE;
        handlePtr->atime = handlePtr->otime = 0;
        handlePtr->stale = NS_FALSE;
        return NS_ERROR;
    }
#if LDAP_API_VERSION >= 3000
    {
        int version = LDAP_VERSION3;
        if (ldap_set_option(handlePtr->ldaph, LDAP_OPT_PROTOCOL_VERSION, &version) != LDAP_SUCCESS) {
            Ns_Log(Error, "nsldap: could not set protocol version to LDAPV3");
            handlePtr->connected = NS_FALSE;
            handlePtr->atime = handlePtr->otime = 0;
            handlePtr->stale = NS_FALSE;
            return NS_ERROR;
        }
        Ns_Log(Notice, "CONNECT protocol version set to LDAP_VERSION3");
    }
#endif

    cred.bv_val = (char *)handlePtr->password;
    cred.bv_len = strlen(handlePtr->password);
    rc = ldap_sasl_bind_s(handlePtr->ldaph, handlePtr->user, LDAP_SASL_SIMPLE, &cred,
                           NULL, NULL,     /* no controls right now */
                           NULL);         /* we don't care about the server's credentials */


    if (rc != LDAP_SUCCESS) {
        Ns_Log(Error, "nsldap: could not bind to server %s: %s",
               handlePtr->host, ldap_err2string(rc));
        return NS_ERROR;
    }
    handlePtr->connected = NS_TRUE;
    handlePtr->atime = handlePtr->otime = time(NULL);

    Ns_Log(Debug, "LDAPConnect returns NS_OK");
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

static bool
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

static Ns_ReturnCode
LDAPPoolTimedGetMultipleHandles(Handle **handles, const char *pool,
                                int nwant, int wait, Context *context)
{
    Handle       *handlePtr;
    Handle      **handlesPtrPtr = handles;
    Pool         *poolPtr;
    Ns_Time       timeoutStruct, *timePtr;
    int           i, ngot;
    Ns_ReturnCode status;

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

static Ns_ReturnCode
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
        prev = PTR2INT(Tcl_GetHashValue(hPtr));
    }
    count = prev + incr;
    if (count == 0) {
        Tcl_DeleteHashEntry(hPtr);
    } else {
        Tcl_SetHashValue(hPtr, INT2PTR(count));
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

static bool
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

static void
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

    Tcl_DStringFree(&handle->ErrorMsg);

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
 *      Return NS_OK if handle is found or NS_ERROR otherwise.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static Ns_ReturnCode
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
        return NS_ERROR;
    }
    *handle = (Handle *) Tcl_GetHashValue(hPtr);
    if (hPtrPtr != NULL) {
        *hPtrPtr = hPtr;
    }
    return NS_OK;
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
LDAPFail(Tcl_Interp *interp, Handle *handle, char *cmdName)
{
    Tcl_AppendResult(interp, "LDAP operation \"", cmdName, "\" failed", NULL);
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

static Ns_ReturnCode
LDAPInterpInit(Tcl_Interp *interp, const void *context)
{

    TCL_CREATEOBJCOMMAND(interp, "ns_ldap", LDAPObjCmd, (ClientData)context, NULL);

    return NS_OK;
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
            listPtr = Tcl_NewStringObj( dn, TCL_INDEX_NONE);
            ldap_memfree(dn);
            return listPtr;
        } else {
            return Tcl_NewStringObj("", TCL_INDEX_NONE);
        }
    }
    listPtr = Tcl_NewListObj(0, (Tcl_Obj **) NULL);
    if (dn != NULL) {
        if (!attrsonly) {
            Tcl_ListObjAppendElement(interp, listPtr,
                                     Tcl_NewStringObj( "dn", TCL_INDEX_NONE));
        }
        Tcl_ListObjAppendElement(interp, listPtr,
                                 Tcl_NewStringObj( dn, TCL_INDEX_NONE));
        ldap_memfree( dn );
    }
    for ( attr = ldap_first_attribute( ld, e, &ber );
          attr != NULL; attr = ldap_next_attribute( ld, e, ber ) ) {
        struct berval **bvals;

        Tcl_ListObjAppendElement(interp, listPtr,
                                 Tcl_NewStringObj( attr, TCL_INDEX_NONE));
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

static int
LdapGetHandleCmd(Tcl_Interp *interp, TCL_SIZE_T objc, Tcl_Obj *const *objv, Context *context)
{
    const char *pool = NULL;
    int timeoutSecs = 0;
    int nhandles = 1;
    Handle *handlePtr = NULL;
    Handle **handlesPtrPtr = NULL;
    Ns_ReturnCode result;
    Ns_ObjvValueRange posintRange1 = {1, INT_MAX};
    Ns_ObjvValueRange posintRange0 = {0, INT_MAX};

    Ns_ObjvSpec opts[] = {
        {"-timeout", Ns_ObjvInt, &timeoutSecs, &posintRange0},
        {NULL, NULL, NULL, NULL}
    };
    Ns_ObjvSpec args[] = {
        {"?pool",     Ns_ObjvString, &pool,     NULL},
        {"?nhandles", Ns_ObjvInt,    &nhandles, &posintRange1},
        {NULL, NULL, NULL, NULL}
    };

    if (Ns_ParseObjv(opts, args, interp, 2, objc, objv) != NS_OK) {
        return TCL_ERROR;
    }

    /*
     * Fallback to default pool, if not provided.
     */
    if (pool == NULL) {
        pool = context->defaultPool;
        if (pool == NULL) {
            Tcl_SetObjResult(interp, Tcl_NewStringObj("no defaultpool configured", TCL_INDEX_NONE));
            return TCL_ERROR;
        }
    }

    if (LDAPPoolAllowable(context, pool) == NS_FALSE) {
        Ns_TclPrintfResult(interp, "no access to pool: '%s'", pool);
        return TCL_ERROR;
    }

    /*
     * Allocate one or more handles.
     */
    if (nhandles == 1) {
        handlesPtrPtr = &handlePtr;
    } else {
        handlesPtrPtr = ns_malloc((size_t)nhandles * sizeof(Handle *));
    }

    result = LDAPPoolTimedGetMultipleHandles(handlesPtrPtr, pool, nhandles, timeoutSecs, context);
    Ns_Log(Debug, "CALL LDAPPoolTimedGetMultipleHandles returned %s", Ns_ReturnCodeString(result));

    if (result == NS_OK) {
        Tcl_DString ds;
        Tcl_DStringInit(&ds);
        for (int i = 0; i < nhandles; ++i) {
            LDAPEnterHandle(interp, handlesPtrPtr[i], context);
            Tcl_DStringAppendElement(&ds, Tcl_GetStringResult(interp));
        }
        Tcl_DStringResult(interp, &ds);
    }

    if (handlesPtrPtr != &handlePtr) {
        ns_free(handlesPtrPtr);
    }

    if (result != NS_OK && result != NS_TIMEOUT) {
        Tcl_AppendResult(interp, "could not allocate ", Tcl_NewIntObj(nhandles),
                         " handle(s) from pool '", pool, "'", NULL);
        return TCL_ERROR;
    }

    return TCL_OK;
}

static int
LdapAddCmd(Tcl_Interp *interp, TCL_SIZE_T objc, Tcl_Obj *const *objv, Handle *handlePtr, const char *cmdName)
{
    const char *ldapId = NULL;
    const char *dn = NULL;
    TCL_SIZE_T  nargs = 0;
    LDAPMod    *mod;
    LDAPMod   **moda;
    int         ret, lrc;

    Ns_ObjvSpec args[] = {
        {"ldapId", Ns_ObjvString, &ldapId, NULL},
        {"dn",     Ns_ObjvString, &dn,     NULL},
        {"?arg",   Ns_ObjvArgs,   &nargs,  NULL},
        {NULL, NULL, NULL, NULL}
    };

    if (Ns_ParseObjv(NULL, args, interp, 2, objc, objv) != NS_OK) {
        return TCL_ERROR;
    } else if (nargs % 2 != 0) {
        Ns_TclPrintfResult(interp, "must provide an even number of attribute/value arguments");
        return TCL_ERROR;
    }

    mod = ns_malloc((size_t)(nargs/2 + 1) * sizeof(LDAPMod));
    moda = ns_malloc((size_t)(nargs/2 + 1) * sizeof(LDAPMod *));
    ret = TCL_OK;

    for (int i = 0; i < nargs / 2; ++i) {
        const char *attr = Tcl_GetString(objv[4 + 2*i]);
        const char *val  = Tcl_GetString(objv[4 + 2*i + 1]);
        int vlen;

        mod[i].mod_op = LDAP_MOD_ADD;
        mod[i].mod_type = (char *)attr;

        if (Tcl_SplitList(interp, val, &vlen, (const char ***)&mod[i].mod_values) != TCL_OK) {
            for (int j = 0; j < i; ++j) {
                Tcl_Free((char *)moda[j]->mod_values);
            }
            ns_free(mod);
            ns_free(moda);
            return TCL_ERROR;
        }

        moda[i] = &mod[i];
    }

    moda[nargs / 2] = NULL;

    lrc = ldap_add_ext_s(handlePtr->ldaph, dn, moda, NULL, NULL);
    if (lrc != LDAP_SUCCESS) {
        Tcl_AppendResult(interp, "nsldap [", cmdName, "]: ", ldap_err2string(lrc), NULL);
        ret = TCL_ERROR;
    }

    for (int i = 0; moda[i]; ++i) {
        Tcl_Free((char *)moda[i]->mod_values);
    }
    ns_free(mod);
    ns_free(moda);

    return ret;
}

static int
LdapBindCmd(Tcl_Interp *interp, TCL_SIZE_T objc, Tcl_Obj *const *objv,
            Handle *handlePtr, const char *UNUSED(cmdName))
{
    const char *ldapId = NULL;
    const char *dn = NULL;
    const char *pass = NULL;
    struct berval berpass, bercred;
    int err;

    Ns_ObjvSpec args[] = {
        {"ldapId", Ns_ObjvString, &ldapId, NULL},
        {"dn",     Ns_ObjvString, &dn,     NULL},
        {"pass",   Ns_ObjvString, &pass,   NULL},
        {NULL, NULL, NULL, NULL}
    };

    if (Ns_ParseObjv(NULL, args, interp, 2, objc, objv) != NS_OK) {
        return TCL_ERROR;
    }

    berpass.bv_val = (char *)pass;
    berpass.bv_len = strlen(pass);
    bercred.bv_val = (char *)handlePtr->password;
    bercred.bv_len = strlen(handlePtr->password);

    err = ldap_sasl_bind_s(handlePtr->ldaph, dn, LDAP_SASL_SIMPLE, &berpass,
                           NULL, NULL, NULL);

    ldap_sasl_bind_s(handlePtr->ldaph, handlePtr->user, LDAP_SASL_SIMPLE, &bercred,
                     NULL, NULL, NULL);

    if (err != LDAP_SUCCESS) {
        Ns_Log(Error, "nsldap: could not bind for %s : %s", dn, ldap_err2string(err));
        Tcl_SetObjResult(interp, Tcl_NewIntObj(0));
        return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_NewIntObj(1));
    return TCL_OK;
}

static int
LdapCompareCmd(Tcl_Interp *interp, TCL_SIZE_T objc, Tcl_Obj *const *objv,
               Handle *handlePtr, const char *cmdName)
{
    const char *ldapId = NULL;
    const char *dn = NULL;
    const char *attr = NULL;
    const char *value = NULL;
    struct berval bvalue;
    int lrc;

    Ns_ObjvSpec args[] = {
        {"ldapId", Ns_ObjvString, &ldapId, NULL},
        {"dn",     Ns_ObjvString, &dn,     NULL},
        {"attr",   Ns_ObjvString, &attr,   NULL},
        {"value",  Ns_ObjvString, &value,  NULL},
        {NULL, NULL, NULL, NULL}
    };

    if (Ns_ParseObjv(NULL, args, interp, 2, objc, objv) != NS_OK) {
        return TCL_ERROR;
    }

    bvalue.bv_val = (char *)value;
    bvalue.bv_len = strlen(value);

    lrc = ldap_compare_ext_s(handlePtr->ldaph, dn, attr, &bvalue, NULL, NULL);
    if (lrc == LDAP_COMPARE_TRUE || lrc == LDAP_COMPARE_FALSE) {
        Tcl_SetObjResult(interp, Tcl_NewIntObj(0));
        return TCL_OK;
    }

    Tcl_AppendResult(interp, "nsldap [", cmdName, "]: ", ldap_err2string(lrc), NULL);
    return TCL_ERROR;
}

static int
LdapDeleteCmd(Tcl_Interp *interp, TCL_SIZE_T objc, Tcl_Obj *const *objv,
              Handle *handlePtr, const char *cmdName)
{
    const char *ldapId = NULL;
    const char *dn = NULL;
    int lrc;

    Ns_ObjvSpec args[] = {
        {"ldapId", Ns_ObjvString, &ldapId, NULL},
        {"dn",     Ns_ObjvString, &dn,     NULL},
        {NULL, NULL, NULL, NULL}
    };

    if (Ns_ParseObjv(NULL, args, interp, 2, objc, objv) != NS_OK) {
        return TCL_ERROR;
    }

    lrc = ldap_delete_ext_s(handlePtr->ldaph, dn, NULL, NULL);
    if (lrc != LDAP_SUCCESS) {
        Tcl_AppendResult(interp, "nsldap [", cmdName, "]: ", ldap_err2string(lrc), NULL);
        return TCL_ERROR;
    }

    return TCL_OK;
}

static int
LdapModifyCmd(Tcl_Interp *interp, TCL_SIZE_T objc, Tcl_Obj *const *objv,
              Handle *handlePtr, const char *cmdName)
{
    const char  *dn;
    LDAPMod     *mod = NULL, **moda = NULL;
    int          count = 0, mode = -1, i = 0, lrc = 0, ret = TCL_OK;

    if (objc < 7) {
        Tcl_WrongNumArgs(interp, 2, objv, "ldapId dn ?add: fld vals ...? ?mod: fld vals ...? ?del: fld vals ...?");
        return TCL_ERROR;
    }

    dn = Tcl_GetString(objv[3]);

    for (i = 4; i < objc; i++) {
        const char *arg = Tcl_GetString(objv[i]);
        if (strcmp(arg, "add:") == 0) {
            mode = LDAP_MOD_ADD;
        } else if (strcmp(arg, "mod:") == 0) {
            mode = LDAP_MOD_REPLACE;
        } else if (strcmp(arg, "del:") == 0) {
            mode = LDAP_MOD_DELETE;
        } else if (mode == LDAP_MOD_ADD || mode == LDAP_MOD_REPLACE) {
            if (objc - i < 2) {
                Tcl_AppendResult(interp, "missing value for attribute ", arg, NULL);
                return TCL_ERROR;
            }
            i++; count++;
        } else if (mode == LDAP_MOD_DELETE) {
            count++;
        } else {
            Tcl_AppendResult(interp, "invalid argument sequence", NULL);
            return TCL_ERROR;
        }
    }

    if (count == 0) return TCL_OK;

    mod = ns_malloc((size_t)(count + 1) * sizeof(LDAPMod));
    moda = ns_malloc((size_t)(count + 1) * sizeof(LDAPMod *));

    mode = -1;
    for (count = 0, i = 4; i < objc; i++) {
        const char *arg = Tcl_GetString(objv[i]);
        const char *attr;

        if (strcmp(arg, "add:") == 0) {
            mode = LDAP_MOD_ADD;
            continue;
        } else if (strcmp(arg, "mod:") == 0) {
            mode = LDAP_MOD_REPLACE;
            continue;
        } else if (strcmp(arg, "del:") == 0) {
            mode = LDAP_MOD_DELETE;
            continue;
        }

        attr = arg;
        mod[count].mod_op = mode;
        mod[count].mod_type = (char *)attr;

        if (mode == LDAP_MOD_DELETE) {
            mod[count].mod_values = NULL;
        } else {
            const char *val = Tcl_GetString(objv[++i]);
            int vlen;
            if (Tcl_SplitList(interp, val, &vlen, (const char ***)&mod[count].mod_values) != TCL_OK) {
                for (int j = 0; j < count; j++) {
                    if (moda[j]->mod_values != NULL) {
                        Tcl_Free((char *)moda[j]->mod_values);
                    }
                }
                ns_free(mod);
                ns_free(moda);
                return TCL_ERROR;
            }
        }

        moda[count] = &mod[count];
        count++;
    }

    moda[count] = NULL;

    lrc = ldap_modify_ext_s(handlePtr->ldaph, dn, moda, NULL, NULL);
    if (lrc != LDAP_SUCCESS) {
        Tcl_AppendResult(interp, "nsldap [", cmdName, "]: ", ldap_err2string(lrc), NULL);
        ret = TCL_ERROR;
    }

    for (i = 0; moda[i]; i++) {
        if (moda[i]->mod_values != NULL)
            Tcl_Free((char *)moda[i]->mod_values);
    }
    ns_free(mod);
    ns_free(moda);

    return ret;
}

static int
LdapModrdnCmd(Tcl_Interp *interp, TCL_SIZE_T objc, Tcl_Obj *const *objv,
              Handle *handlePtr, const char *cmdName)
{
    const char *ldapId = NULL;
    const char *dn = NULL;
    const char *rdn = NULL;
    int deloldrdn = 0;
    int lrc;

    Ns_ObjvSpec args[] = {
        {"ldapId",     Ns_ObjvString, &ldapId,    NULL},
        {"dn",         Ns_ObjvString, &dn,        NULL},
        {"rdn",        Ns_ObjvString, &rdn,       NULL},
        {"?deloldrdn", Ns_ObjvBool,   &deloldrdn, NULL},
        {NULL, NULL, NULL, NULL}
    };

    if (Ns_ParseObjv(NULL, args, interp, 2, objc, objv) != NS_OK) {
        return TCL_ERROR;
    }

    lrc = ldap_rename_s(handlePtr->ldaph, dn, rdn, NULL, deloldrdn, NULL, NULL);
    if (lrc != LDAP_SUCCESS) {
        Tcl_AppendResult(interp, "nsldap [", cmdName, "]: ", ldap_err2string(lrc), NULL);
        return TCL_ERROR;
    }

    return TCL_OK;
}

static int
LdapSearchCmd(Tcl_Interp *interp, TCL_SIZE_T objc, Tcl_Obj *const *objv,
              Handle *handlePtr, const char *cmdName)
{
    const char *base = NULL;
    const char *filter = "objectClass=*";
    const char **attrs = NULL;
    int scope = LDAP_SCOPE_BASE;
    int attrsonly = 0;
    int namesonly = 0;
    int msgid, rc;
    Tcl_Obj **attrv = NULL;
    TCL_SIZE_T attrc = 0;
    LDAPMessage *result, *e;
    Tcl_Obj *listPtr;

    static Ns_ObjvTable scopes[] = {
        {"base",     LDAP_SCOPE_BASE},
        {"onelevel", LDAP_SCOPE_ONELEVEL},
        {"subtree",  LDAP_SCOPE_SUBTREE},
        {NULL,       0}
    };

    Ns_ObjvSpec opts[] = {
        {"-scope", Ns_ObjvIndex, &scope,     scopes},
        {"-attrs", Ns_ObjvBool,  &attrsonly, NULL},
        {"-names", Ns_ObjvBool,  &namesonly, NULL},
        {NULL, NULL, NULL, NULL}
    };

    Ns_ObjvSpec args[] = {
        {"base",    Ns_ObjvString, &base,   NULL},
        {"?filter", Ns_ObjvString, &filter, NULL},
        {"?attrs",  Ns_ObjvArgs,   &attrv,  &attrc},
        {NULL, NULL, NULL, NULL}
    };

    if (Ns_ParseObjv(opts, args, interp, 3, objc, objv) != NS_OK) {
        return TCL_ERROR;
    }

    if (namesonly) {
        attrsonly = 1;
    }

    if (attrc > 0) {
        attrs = ns_malloc((size_t)(attrc + 1) * sizeof(char *));
        for (TCL_SIZE_T i = 0; i < attrc; ++i) {
            attrs[i] = Tcl_GetString(attrv[i]);
        }
        attrs[attrc] = NULL;
    }

    rc = ldap_search_ext(handlePtr->ldaph, base, scope, filter,
                         (char **)attrs, attrsonly,
                         NULL, NULL, NULL,
                         LDAP_NO_LIMIT, &msgid);
    if (attrs != NULL) {
        ns_free(attrs);
    }

    if (rc != LDAP_SUCCESS) {
        Tcl_AppendResult(interp, "nsldap [", cmdName, "]: couldn't perform search: ",
                         ldap_err2string(rc), NULL);
        return TCL_ERROR;
    }

    listPtr = Tcl_NewListObj(0, NULL);
    while ((rc = ldap_result(handlePtr->ldaph, msgid, 0, &timeout, &result)) == LDAP_RES_SEARCH_ENTRY) {
        for (e = ldap_first_entry(handlePtr->ldaph, result);
             e != NULL;
             e = ldap_next_entry(handlePtr->ldaph, e)) {
            Tcl_ListObjAppendElement(interp, listPtr,
                                     Entry2List(interp, handlePtr->ldaph, e, attrsonly, namesonly));
        }
        ldap_msgfree(result);
    }

    if (rc == -1 || rc == 0) {
        Tcl_DecrRefCount(listPtr);
        if (rc == -1) {
            int err;
            char *dn;
            ldap_parse_result(handlePtr->ldaph, result, &err, &dn, NULL, NULL, NULL, 0);
            Tcl_AppendResult(interp, "nsldap [", cmdName, "]: couldn't retrieve search results: ",
                             ldap_err2string(err), NULL);
        } else {
            Tcl_AppendResult(interp, "nsldap [", cmdName, "]: couldn't retrieve search results: timeout", NULL);
        }
        ldap_msgfree(result);
        return TCL_ERROR;
    }

    ldap_msgfree(result);
    Tcl_SetObjResult(interp, listPtr);
    return TCL_OK;
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
typedef enum {
    CMD_ADD,
    CMD_BIND,
    CMD_BOUNCEPOOL,
    CMD_COMPARE,
    CMD_CONNECTED,
    CMD_DELETE,
    CMD_DISCONNECT,
    CMD_GETHANDLE,
    CMD_HOST,
    CMD_MODIFY,
    CMD_MODRDN,
    CMD_PASSWORD,
    CMD_POOLNAME,
    CMD_POOLS,
    CMD_RELEASEHANDLE,
    CMD_SEARCH,
    CMD_USER
} LdapSubcommand;


static const Ns_ObjvTable ldapCmdTable[] = {
    {"add",           CMD_ADD},
    {"bind",          CMD_BIND},
    {"bouncepool",    CMD_BOUNCEPOOL},
    {"compare",       CMD_COMPARE},
    {"connected",     CMD_CONNECTED},
    {"delete",        CMD_DELETE},
    {"disconnect",    CMD_DISCONNECT},
    {"gethandle",     CMD_GETHANDLE},
    {"host",          CMD_HOST},
    {"modify",        CMD_MODIFY},
    {"modrdn",        CMD_MODRDN},
    {"password",      CMD_PASSWORD},
    {"poolname",      CMD_POOLNAME},
    {"pools",         CMD_POOLS},
    {"releasehandle", CMD_RELEASEHANDLE},
    {"search",        CMD_SEARCH},
    {"user",          CMD_USER},
    {NULL,            0}
};

static int
LDAPObjCmd(ClientData ctx, Tcl_Interp *interp, TCL_SIZE_T objc, Tcl_Obj *const* objv)
{

    Handle         *handlePtr = NULL;
    const char     *cmdName;
    Tcl_Obj        *cmdObj;
    const char     *pool = NULL;
    Context        *context;
    LdapSubcommand  cmd;
    Tcl_HashEntry  *hPtr;
    const char     *ldapId = NULL;
    TCL_SIZE_T      nargs = 0;
    int             opt;

    if (objc < 2) {
        Tcl_AppendResult(interp, "wrong # of args: should be \"",
                         Tcl_GetString(objv[0]), " command ?args ...?", NULL);
        return TCL_ERROR;
    }

    cmdObj = objv[1];
    cmdName = Tcl_GetString(cmdObj);
    if (Tcl_GetIndexFromObjStruct(interp, cmdObj, ldapCmdTable,
                                  (int)sizeof(ldapCmdTable[0]),
                                  "subcommand", TCL_EXACT, &opt) != TCL_OK) {
        return TCL_ERROR;
    }
    cmd = (LdapSubcommand)opt;
    context = (Context *)ctx;

    switch (cmd) {
    case CMD_POOLS: {
        if (Ns_ParseObjv(NULL, NULL, interp, 2, objc, objv) != NS_OK) {
            return TCL_ERROR;
        } else {
            pool = context->allowedPools;
            if (pool != NULL) {
                while (*pool != '\0') {
                    Tcl_AppendElement(interp, pool);
                    pool = pool + strlen(pool) + 1;
                }
            }
        }
        return TCL_OK;
    }
    case CMD_BOUNCEPOOL: {
        int         result = TCL_OK;
        Ns_ObjvSpec largs[] = {
            {"pool", Ns_ObjvString,  &pool, NULL},
            {NULL, NULL, NULL, NULL}
        };
        if (Ns_ParseObjv(NULL, largs, interp, 2, objc, objv) != NS_OK) {
            result = TCL_ERROR;
        } else if  (LDAPBouncePool(pool, context) == NS_ERROR) {
            Tcl_AppendResult(interp, "could not bounce: ", pool, NULL);
            result = TCL_ERROR;
        }
        return result;
    }

    case CMD_GETHANDLE: {
        return LdapGetHandleCmd(interp, objc, objv, context);
    }

    case CMD_ADD:
    case CMD_BIND:
    case CMD_COMPARE:
    case CMD_CONNECTED:
    case CMD_DELETE:
    case CMD_DISCONNECT:
    case CMD_HOST:
    case CMD_MODIFY:
    case CMD_MODRDN:
    case CMD_PASSWORD:
    case CMD_POOLNAME:
    case CMD_RELEASEHANDLE:
    case CMD_SEARCH:
    case CMD_USER: {
        Ns_ObjvSpec     handleArgs[] = {
            {"ldapId", Ns_ObjvString, &ldapId, NULL},
            {"?arg",   Ns_ObjvArgs,   &nargs,  NULL},
            {NULL, NULL, NULL, NULL}
        };

        /*
         * All remaining commands require a valid ldap handle
         */
        if (Ns_ParseObjv(NULL, handleArgs, interp, 2, objc, objv) != NS_OK) {
            return TCL_ERROR;
        }

        if (LDAPGetHandle(interp, ldapId, &handlePtr, &hPtr, context) != NS_OK) {
            return TCL_ERROR;
        }

        break;
    } }

    /*
     * "handlePtr" is now initialized an can be used in the subcommands below.
     */
    assert(handlePtr != NULL);
    Tcl_DStringFree(&handlePtr->ErrorMsg);

    switch (cmd) {
    case CMD_POOLS:
    case CMD_BOUNCEPOOL:
    case CMD_GETHANDLE:
        /*
         * handled already above.
         */
        return TCL_OK;


    case CMD_CONNECTED:
    case CMD_DISCONNECT:
    case CMD_HOST:
    case CMD_PASSWORD:
    case CMD_POOLNAME:
    case CMD_RELEASEHANDLE:
    case CMD_USER: {
        if (nargs > 0) {
            Ns_ObjvSpec largs1[] = {
                {"ldapId", Ns_ObjvString, &ldapId, NULL},
                {NULL, NULL, NULL, NULL}
            };
            /*
             * If nargs, the number of arguments is not correct. Use
             * Ns_ParseObjv() just to generate a consistent error message.
             */
            if (Ns_ParseObjv(NULL, largs1, interp, 2, objc, objv) != NS_OK) {
                return TCL_ERROR;
            }
        }
        if (cmd == CMD_CONNECTED) {
            Tcl_SetObjResult(interp, Tcl_NewIntObj(handlePtr->connected));
        } else if (cmd == CMD_DISCONNECT) {
            LDAPDisconnect(handlePtr);
        } else if (cmd == CMD_HOST) {
            Tcl_SetObjResult(interp, Tcl_NewStringObj(handlePtr->host, TCL_INDEX_NONE));
        } else if (cmd == CMD_PASSWORD) {
            Tcl_SetObjResult(interp,  Tcl_NewStringObj(handlePtr->password, TCL_INDEX_NONE));
        } else if (cmd == CMD_POOLNAME) {
            Tcl_SetObjResult(interp, Tcl_NewStringObj(handlePtr->poolname, TCL_INDEX_NONE));
        } else if (cmd == CMD_RELEASEHANDLE) {
            Ns_Log(Debug, "nsldap: releasehandle %s", ldapId);
            Tcl_DeleteHashEntry(hPtr);
            LDAPPoolPutHandle(handlePtr);
        } else if (cmd == CMD_USER) {
            Tcl_SetObjResult(interp, Tcl_NewStringObj(handlePtr->user, TCL_INDEX_NONE));
        }
        return TCL_OK;
    }

    case CMD_ADD:
        return LdapAddCmd(interp, objc, objv, handlePtr, cmdName);

    case CMD_BIND:
        return LdapBindCmd(interp, objc, objv, handlePtr, cmdName);

    case CMD_COMPARE:
        return LdapCompareCmd(interp, objc, objv, handlePtr, cmdName);

    case CMD_DELETE:
        return LdapDeleteCmd(interp, objc, objv, handlePtr, cmdName);

    case CMD_MODIFY:
        return LdapModifyCmd(interp, objc, objv, handlePtr, cmdName);

    case CMD_MODRDN:
        return LdapModrdnCmd(interp, objc, objv, handlePtr, cmdName);

    case CMD_SEARCH:
        return LdapSearchCmd(interp, objc, objv, handlePtr, cmdName);

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
