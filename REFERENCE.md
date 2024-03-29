# Reference

<!-- DO NOT EDIT: This document was generated by Puppet Strings -->

## Table of Contents

### Classes

* [`profile_jenkins`](#profile_jenkins): Install and configures Jenkins
* [`profile_jenkins::backup`](#profile_jenkinsbackup): Configure jenkins backups

## Classes

### <a name="profile_jenkins"></a>`profile_jenkins`

Install and configures Jenkins

#### Examples

##### 

```puppet
include profile_jenkins
```

#### Parameters

The following parameters are available in the `profile_jenkins` class:

* [`use_security`](#use_security)
* [`auth_strategy_class`](#auth_strategy_class)
* [`auth_matrix_permissions`](#auth_matrix_permissions)
* [`security_realm_class`](#security_realm_class)
* [`security_realm_plugin`](#security_realm_plugin)
* [`security_realm_settings`](#security_realm_settings)

##### <a name="use_security"></a>`use_security`

Data type: `Boolean`

Enable security for Jenkins

##### <a name="auth_strategy_class"></a>`auth_strategy_class`

Data type: `String`

Class name of the authorization strategy to use

##### <a name="auth_matrix_permissions"></a>`auth_matrix_permissions`

Data type: `Optional[Array[Hash]]`

(optional) If matrix-based authorization is used, provide a list of rules. Each rule
hash consists of type (GROUP or USER), action (class name of the Jenkins action), and
entity_name (the name of the group or user)

##### <a name="security_realm_class"></a>`security_realm_class`

Data type: `String`

Class name of the security realm to use

##### <a name="security_realm_plugin"></a>`security_realm_plugin`

Data type: `Optional[String]`

(optional) If using a security realm provided by a plugin, provide the name of the
plugin

##### <a name="security_realm_settings"></a>`security_realm_settings`

Data type: `Hash`

Settings for the selected security realm

### <a name="profile_jenkinsbackup"></a>`profile_jenkins::backup`

Configure jenkins backups

#### Parameters

The following parameters are available in the `profile_jenkins::backup` class:

* [`locations`](#locations)

##### <a name="locations"></a>`locations`

Data type: `Array[String]`

files and directories that are to be backed up#
include profile_xcat::master::backup

