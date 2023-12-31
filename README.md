# LDAP client library for NaviServer #

This is nsldap, an LDAP module for NaviServer. What this module does
is provide a new command (nsldap) inside the Tcl Interpreter in
NaviServer that implements a subset of the LDAP functionality.

The module is modelled after the DB API of NaviServer in the sense
that you define "pools" in your config file for NaviServer and then
get "handles" to the connections allowed in those pools from your
code.

The actual LDAP API is modelled after sensus consulting's LDAP
extensions for Tcl. It is described later in this document.

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


Application Programmer's Interface (API)
----------------------------------------

This module provides a new command called ns_ldap which is modelled
after the ns_db command in some respects.

#### `ns_ldap pools`
  Gives the list of available pools

#### `ns_ldap bouncepool /poolname/`
  Closes all handles on the Pool

#### `ns_ldap gethandle ?-timeout timeout? ?pool? ?nhandles?  `
  Gets ?nhandles? handles from pool ?pool? or the defaultpool
  defined in the config file if ?pool? is omitted. If ?nhandles? is
  omitted, 1 handle is returned.
    
  An optional timeout ?timeout? can be specified.

#### `ns_ldap poolname /ldaph/`
  Returns the name of the pool referenced by the handle $ldaph

#### `ns_ldap password /ldaph/`
  Returns the password used to bind to the pool referenced by $ldaph

#### `ns_ldap user /ldaph/`
  Returns the BindDN used to bind to the pool referenced by $ldaph

#### `ns_ldap host /ldaph/`
  Returns the host to which the pool referenced by $ldaph is bound

#### `ns_ldap disconnect /ldaph/`
  Disconnects the pool referenced by $ldaph

#### `ns_ldap releasehandle /ldaph/`
  Releases the handle referenced by $ldaph (which was obtained using ns_ldap gethandle)

#### `ns_ldap connected /ldap/`
  Checks if the handle $ldaph references a pool that is connected.

#### `ns_ldap add /ldaph/ /dn/ ?attr value?`
  Adds an object to the LDAP directory using the handle $ldaph.
  
*   `dn` is the DN of the object to be added
*   Pairs `?attr value?` can be specified to set attributes to
    values. If the attribute is multivalued, a Tcl list can be provided.

#### `ns_ldap compare /ldaph/ /dn/ /attr/ /value/`
  Issues a compare, returns 1 (true) if attr matches value, 0
  otherwise.

#### `ns_ldap delete /ldaph/ dn`

  Removes the object referenced by dn from the LDAP tree. Most
  directories will not allow you to delete an object that has
  children.


#### `ns_ldap modify /ldaph/ ?add: fld valList ...? ?mod: fld valList ...? ?del: fld valList ...?`

Modifies an entry in the directory. This is best shown by an example.
The following adds two objectclass attributes, deletes the junkAttr
attribute and replaces any existing cn attributes with the single value
"Foo Bar": 

```
ns_ldap modify $ldaph $dn add: objectclass [list person inetOrgPerson] del: junkAttr mod: cn [list "Foo Bar"]
```

#### `ns_ldap modrdn /ldaph/ /dn/ /rdn/ ?deloldrdn?`

Renames an object (changes the rdn).

#### `ns_ldap bind /ldaph/ /username/ /password/`

This command is meant to be used for credentials check only.

*     Issues an LDAP bind with the username and password, returns 1 (true) if
      the username/password combination
      is valid for authentication, 0 otherwise.
      
*     Issues a second bind with the original credentials right afterwards to
      prevent working on LDAP as the user authenticated with the application.


#### `ns_ldap search /ldaph/ ?-scope [base onelevel subtree]? ?-attrs bool? ?-names bool? /base/ ?filter?`

Perhaps the most useful command. it searches the LDAP tree for particular
entries. Returns a list of entries where each entry is in itself a list
of attr value pairs. This is suitable for use with array set. The values
associated with the attr are a Tcl list since attributes can have multiple
values.

If no filter is provided, the default filter (objectclass=*) is used.
If attribute names are provided after the filter, only the named 
attributes will be returned. The available options are:

*   `-attrs bool`
    Returns only the names of the attributes in the matching objects.
    When this is true, the returned list contains lists in which the
    first entry is the dn of the matched object and the subsequent fields
    are the matched attributes.
    (default: false)

*   `-names bool`
    Returns only the dn names of the matching objects. When this is true
    the returned list contains all matched dn's as elements.
    (default: false)

*   `-scope enum`
    Specifies the scope of the search. Can be base, one, or sub.
    (default: base)
