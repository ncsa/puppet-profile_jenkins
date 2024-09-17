# @summary Install and configures Jenkins
#
# @author Yan Zhan
#
# @example
#   include profile_jenkins
#
# @param use_security
#   Enable security for Jenkins
#
# @param auth_strategy_class
#   Class name of the authorization strategy to use
#
# @param auth_matrix_permissions
#   (optional) If matrix-based authorization is used, provide a list of rules. Each rule
#   hash consists of type (GROUP or USER), action (class name of the Jenkins action), and
#   entity_name (the name of the group or user)
#
# @param security_realm_class
#   Class name of the security realm to use
#
# @param security_realm_plugin
#   (optional) If using a security realm provided by a plugin, provide the name of the
#   plugin
#
# @param security_realm_settings
#   Settings for the selected security realm
#
class profile_jenkins (

  Boolean $use_security,
  String $auth_strategy_class,
  Optional[Array[Hash]] $auth_matrix_permissions,
  String $security_realm_class,
  Optional[String] $security_realm_plugin,
  Hash $security_realm_settings,

) {
  include java
  include apache::mod::auth_openidc
  include jenkins

  augeas { 'Jenkins/useSecurity':
    incl    => '/var/lib/jenkins/config.xml',
    lens    => 'Xml.lns',
    changes => "set hudson/useSecurity/#text ${use_security}",
    notify  => Service['jenkins'],
  }

  augeas { 'Jenkins/authStrategy':
    incl    => '/var/lib/jenkins/config.xml',
    lens    => 'Xml.lns',
    changes => "set hudson/authorizationStrategy/#attribute/class ${auth_strategy_class}",
    notify  => Service['jenkins'],
  }

  $auth_matrix_permissions.each |Hash $rule_hash| {
    $permission_string = "${rule_hash['type']}:${rule_hash['action']}:${rule_hash['entity_name']}"

    augeas { "Jenkins/authMatrixPermission-${permission_string}":
      incl    => '/var/lib/jenkins/config.xml',
      lens    => 'Xml.lns',
      changes => "set hudson/authorizationStrategy/permission[last()+1]/#text ${permission_string}",
      onlyif  => "values hudson/authorizationStrategy/permission/#text \
                  not_include ${permission_string}",
      notify  => Service['jenkins'],
    }
  }

  augeas { 'Jenkins/securityRealm':
    incl    => '/var/lib/jenkins/config.xml',
    lens    => 'Xml.lns',
    changes => "set hudson/securityRealm/#attribute/class ${security_realm_class}",
    notify  => Service['jenkins'],
  }

  augeas { 'Jenkins/securityRealmPlugin':
    incl    => '/var/lib/jenkins/config.xml',
    lens    => 'Xml.lns',
    changes => "set hudson/securityRealm/#attribute/plugin ${security_realm_plugin}",
    onlyif  => 'match hudson/securityRealm/#attribute/plugin size == 0',
    notify  => Service['jenkins'],
  }

  $security_realm_settings.each |$key, $value| {
    augeas { "Jenkins/securityRealmSettings-${key}":
      incl    => '/var/lib/jenkins/config.xml',
      lens    => 'Xml.lns',
      changes => "set hudson/securityRealm/${key}/#text ${value}",
      notify  => Service['jenkins'],
    }
  }

  ensure_resource('user', $jenkins::user, {
      ensure      => present,
      gid         => $jenkins::group,
      home        => $jenkins::localstatedir,
      shell       => '/sbin/nologin',
      managehome  => false,
      system      => true,
    }
  )

  $dir_params = {
    ensure => directory,
    owner  => $jenkins::user,
    group  => $jenkins::group,
    mode   => '0750',
  }
  ensure_resource('file', $jenkins::localstatedir, $dir_params)
  ensure_resource('file', $jenkins::plugin_dir, $dir_params)
  ensure_resource('file', $jenkins::job_dir, $dir_params)
}
