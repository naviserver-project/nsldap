# LDAP client library for NaviServer #

This is nsldap, an LDAP module for NaviServer. What this module does
is provide a new command (nsldap) inside the Tcl Interpreter in
NaviServer that implements a subset of the LDAP functionality.

The module is modelled after the DB API of NaviServer in the sense
that you define "pools" in your config file for NaviServer and then
get "handles" to the connections allowed in those pools from your
code.

The actual LDAP API is modeled after Sensus Consulting's LDAP
extensions for Tcl, extended with NaviServer-style pooling.

The compilation requires the LDAP, sasl and OpenSSL libraries.
On a debian system, you might have to install these with the
following command

```
  apt-get install libsasl2-dev libldap2-dev libssl-dev
```


A NOTE ABOUT ORACLE
-------------------

Oracle 8i provides an LDAP implementation within the client
libraries which is not entirely compatible with OpenLDAP 
semantics. If you're running a NaviServer that uses the ora8.so
module (provided by ArsDigita) and you run into trouble with
nsldap.so (coredumping the nsd program in an ns_ldap add operation
for example) you should apply the following workaround courtesy
of Otto Solares <solca@galileo.edu>

WORKAROUND FOR RUNNING NSLDAP WITH ORACLE
-----------------------------------------
The problem is that the NaviServer nsd program loads the db drivers
first and then the rest of the modules. On some operating systems,
Solaris for instance, the dynamic linker resolves the symbols with
the first library that contains them. Since the libclntcsh provided
with oracle provides an implementation of all the LDAP API that
collides with OpenLDAP's API provided with libldap and liblber 
(which are linked with nsldap.so) the dynamic linker uses the Oracle
provided functions which are not fully compatible with nsldap.

As a workaround you can link the nsd binary directly
with OpenLDAP libraries to force the dynamic linker to resolve the
symbols using libldap and liblber. To do this, simply modify the
Makefile.global (in naviserver's include subdirectory) and change
the line:

```
LIBS+=-lsocket -lnsl -ldl -lposix4 -lthread -lresolv -R $(RPATH)
```

with

```
LIBS+=-lsocket -lnsl -ldl -lposix4 -lthread -lresolv -lldap -llber -R $(RPATH)
```
   
where appropriate for your Operating System.


Configuring the nsldap Module in NaviServer's config.tcl file
------------------------------------------------------------

In order to use the ns_ldap command you should first configure the
pools in your NaviServer's config.tcl file. This is the file that you
pass to the nsd binary in the Command Line when you start it up. Note
that this is *after* compiling an installing the nsldap.so module.

You should add the following lines: 

```
   ns_section ns/server/${servername}/modules {
      ns_param   nsldap ${bindir}/nsldap.so
   }
   # 
   # nsldap pool ldap
   #

   ns_section ns/ldap/pool/ldap {
      ns_param user "cn=Manager, o=Universidad Galileo"
      ns_param password "YourPasswordHere"
      ns_param host "ldap.galileo.edu"
      ns_param connections 1
      ns_param verbose On
      ns_param port 389   ;# ldaps uses: 636
      ns_param schema ldap
   }
   # 
   # nsldap pools
   #
   ns_section ns/ldap/pools {
      ns_param ldap ldap
   }
   #
   # nsldap default pool
   #
   ns_section ns/server/${servername}/ldap {
      ns_param Pools *
      ns_param DefaultPool ldap
   }
```
   
If you look at this carefully you'll see it's almost the same as the
database pools.


---

## Tcl API Reference

The `ns_ldap` command supports the following subcommands:


### `ns_ldap pools`
Returns the list of configured pool names available to the current
server context.

### `ns_ldap bouncepool /poolname/`
Closes and reinitializes all handles in the named pool.

### `ns_ldap gethandle ?-timeout /timeout/? ?/poolname/? ?/nhandles/?`
Fetches one or more LDAP handles from the specified pool. If no pool is given, the default is used.

- `-timeout`: Optional timeout in seconds.
- `poolname`: Optional; pool to pull from.
- `nhandles`: Optional; number of handles to retrieve (default 1).

Returns a handle name or a list of handle names.

### `ns_ldap poolname <ldaph>`
Returns the pool name associated with the given handle.

#### `ns_ldap poolname /ldaph/`
Returns the password used to bind the connection represented by `/ldaph/`.

#### `ns_ldap password /ldaph/`
Returns the password used to bind the connection represented by `/ldaph/`.

#### `ns_ldap user /ldaph/`
Returns the user (bind DN) of the connection.

#### `ns_ldap host /ldaph/`
Returns the hostname of the server connected by this handle.

#### `ns_ldap disconnect /ldaph/`
Closes the underlying LDAP connection associated with the handle.

#### `ns_ldap releasehandle /ldaph/`
Releases the handle back to its pool.

#### `ns_ldap connected /ldap/`
Returns 1 if the connection is alive, 0 otherwise.

#### `ns_ldap add /ldaph/ /dn/ /attr1/ /val1/ /attr2/ /val2/ ...`
Adds an LDAP object at the given DN.

- Accepts pairs of attribute/value.
- Multivalued attributes must be passed as a Tcl list in `valN`.

Example:
```tcl
ns_ldap add $lh "cn=John Doe,dc=example,dc=com" givenName John sn Doe objectClass {person inetOrgPerson}
```

### `ns_ldap compare /ldaph/ /dn/ /attr/ /value/`
Compares the attribute at `dn` with `value`. Returns 1 for match, 0 for no match.


### `ns_ldap delete /ldaph/ /dn/`
Deletes the LDAP entry at the given DN.


### `ns_ldap modify /ldaph/ /dn/ ?add: attr valList ...? ?mod: attr valList ...? ?del: attr ...?`
Performs attribute modifications on an entry.

- `add:` adds values to the attribute.
- `mod:` replaces the attribute values.
- `del:` deletes the attribute entirely.

Example:
```tcl
ns_ldap modify $lh $dn \
    add: objectClass [list person inetOrgPerson] \
    del: junkAttr \
    mod: cn [list "Foo Bar"]
```


### `ns_ldap modrdn /ldaph/ /dn/ /newrdn/ ?/deloldrdn/?`
Changes the relative distinguished name (RDN) of an LDAP entry.

- `deloldrdn`: Boolean flag indicating whether to delete the old RDN.


### `ns_ldap bind /ldaph/ /username/ /password/`
Checks whether the given username/password combination is valid via a bind.

- On success, rebinds to the original service credentials.
- Returns 1 if credentials are valid, 0 otherwise.


### `ns_ldap search /ldaph/ ?-scope base|onelevel|subtree? ?-attrs bool? ?-names bool? /base/ ?/filter/? ?/attr/ ...?`
Performs a search on the directory.

- `base`: Base DN to search from.
- `filter`: Optional filter string. Default: `(objectClass=*)`.
- `attr`: Optional list of attribute names to return.
- `-scope`: Search scope. Default is `base`.
- `-attrs`: If true, only return attribute names (no values).
- `-names`: If true, return only DN strings.

Returns a Tcl list of entries, each as a list suitable for Tcl `dict` or `array set`.


---

## License

BSD-like license, inherited from NaviServer and OpenLDAP conventions.
