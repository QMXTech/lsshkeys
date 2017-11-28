# LSSHKeys

## Synopsis

> Fetch SSH Keys from LDAP - V1.0.0
> Copyright (C) 2017 QuantuMatriX Software, a QuantuMatriX Technologies Cooperative Partnership
>
> This utility allows retrievel of SSH keys from an LDAP directory. Please see the man pages for more details, or visit the LSSHKeys website at 'https://git.qmx-software.com/open-source/lsshkeys'.
>
> 'LSSHKeys' is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

## Dependencies

> ### GNU Linux and Apple macOS
>
>> #### Compiler
>> * Clang >= 5.0.0 or GCC >= 7.2.0
>>
>> #### Libraries
>> * LDAP
>>
>> #### Tools
>> * CMake >= 3.9.3
>
> ### Microsoft Windows
>
>> This utility is not supported on a Microsoft Windows platform.

## Requirements

> LSSHKeys requires a working LDAP server and an appropriate attributetype in the LDAP server schema to fetch from the LDAP server (typically 'sshPublicKey') storing the value to output, and an objectclass in the LDAP server schema containing that attribute type.  
>
> Typically this attributetype would be defined as follows:
> ```
> ( 1.3.6.1.4.1.24552.500.1.1.1.13
>    NAME 'sshPublicKey'
>    DESC 'SSH Public Key'
>    EQUALITY octetStringMatch
>    SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
> ```  
> An example schema containing the default attributetype ('sshPublicKey') and an auxiliary objectclass that can be used to add this attributetype to an existing installation ('ssh') is available in the docs directory. The attributetype (+/- objectclass) may be pulled into a custom schema, they may be rewritten or another attributetype may be used; however, additional attributetypes will be required when using this with [nss-pam-ldapd](https://arthurdejong.org/nss-pam-ldapd/). _Please note this schema may not be complete or may conflict with other similar schemas and is provided as an example_.
>
> To install the schema on an OpenLDAP server using slapd.conf:
>
> * Copy 'sshPublicKey.openldap.schema' to the schema directory for your OpenLDAP installation (typically /etc/ldap/schema).
> * Add a new 'include' line to your slapd.conf. It should look something like the following: 
> ```
> include /etc/ldap/schema/sshPublicKey.schema
> ```
>
> * Restart slapd and make sure the new attributetype and objectclass are available in the schema.
>
> To install the schema on an OpenLDAP server using olc:
>
> * Import 'sshPublicKey.openldap-olc.ldif' using the `ldapadd` command. This will probably look something like the following:
> ```
> ldapadd -D '<rootdn>' -W -f sshPublicKey.openldap-olc.ldif
> ```
> (where \<rootdn\> is the rootdn as configured in olc, or another user with write access to 'cn=config'; you will be asked for the corresponding password)
>
> * Make sure the new attributetype and objectclass are available in the schema. You may have to restart slapd.
>
>> *__Note:__ One can also import a schema ldif file while slapd is offline using* `slapadd`*; however the schema indexes must be known to use this method and it requires adding the schema indexes being created to the ldif file.*
>
> To install the schema on a 389 Directory server:
>
> * Copy 'sshPublicKey.389.schema' to '/etc/dirsrv/slapd-<instance_name>/schema/<\?\?>sshPublicKey.ldif' (where '<instance_name>' denotes your slapd instance name, and '<\?\?>' denotes the load order key to give to this schema).
>
> * Restart slapd and make sure the new attributetype and objectclass are available in the schema.
>
> To install the schema on an ApacheDS server:
>
> * Import 'sshPublicKey.apacheds.schema' using Apache Directory Studio, convert it to an LDIF and import it into the ApacheDS server. More details can be found in the [ApacheDS documentation](https://directory.apache.org/apacheds/basic-ug/2.3.1-adding-schema-elements.html).
>
> To install the schema on an Oracle Directory server:
>
> * Import 'sshPublicKey.oracle.ldif' using the `ldapmodify` command. More details can be found in the [Oracle Directory Server documentation](https://docs.oracle.com/cd/E20295_01/html/821-1220/bcasv.html).
>
> To install the schema on a Microsoft Active Directory server:
>
> * _Active Directory is currently not supported._
>
> To install the schema on a Micro Focus (Novell) eDirectory server:
>
> * _eDirectory is currently not supported._

## Building

> To build using CMake, use the following steps:
>
> * Navigate to the project's root directory, and create a new directory called 'build'.
> * Enter the 'build' directory and run the following command (replacing '[GENERATOR]' with the name of the desired CMake generator; note that only Clang and GCC-based compilers are currently supported):
>
>> cmake -G "[GENERATOR]" ..
>
> * After the project files are fully generated, build in the usual manner.  The following targets are supported:
>
>> * all (default; includes 'debug' and 'release')
>> * debug
>> * relwithdebinfo
>> * release
>> * minsizerel
>> * install (only targets actually built will be installed)
>> * uninstall

## Installing

> To install on any platform, use the 'install' target of the generated project files.  

## Configuring

> LSSHKeys requires a mimimum of the 'base' and 'uri' parameters in its configuration file. An example configuration file which provides a description of each configuration parameter is included and will be installed to the compiled-in configuration directory (typically '/etc') as the default configuration file. Descriptions of each configuration parameter are also available in the installed manpage **lsshkeys.conf**(5).

## Running

> LSSHKeys is typically invoked by the SSH server by setting the SSH server to use LSSHKeys as its **AuthorizedKeysCommand** (see the manpage **sshd_config**(5)).  
>
> LSSHKeys accepts the following options:  
>
> * **--config** _FILE_, **--conf** _FILE_, **-c** _FILE_  
> Loads the alternate configuration file _FILE_.  
>
> * **--debug**, **--dbg**, **-d**  
> Enable debugging mode.  LSSHKeys will send verbose debugging messages to stderr.  LSSHKeys will otherwise handle connections as usual. This is functionally equivalent to setting **log stdio** and **loglevel debug** in the configuration file. This option is for debugging purposes only.
>
> * **--help**, **--version**, **-h**, **-v**, **-?**
> Display version information and help to stdout, then exit.
>
>> _These options are not case sensitive._
>
> LSSHKeys will only ever output the result attribute value to stdout (except when run with a variant of --help, see above).  If a variant of **--debug** is specified, or if **log stderr** is set, LSSHKeys will output those messages to stderr.
>
> LSSHKeys returns **0** (**EXIT\_SUCCESS**) when the operation was a success, and **1** (**EXIT\_FAILURE**) when the operation has failed.

## Uninstalling

> To uninstall on any platform, use the 'uninstall' target of the generated project files.

## Contacts and Support

> * Site: 'https://git.qmx-software.com/open-source/lsshkeys'
> * Forums: 'https://forums.qmx-software.com/lsshkeys' (Currently Unavailable)
> * Bug Tracker: 'https://git.qmx-software.com/open-source/lsshkeys/issues'
> * Email: 'support@qmx-software.com'
