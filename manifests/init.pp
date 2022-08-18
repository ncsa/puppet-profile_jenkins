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
){

  include ::java
  include ::jenkins
  include ::apache::mod::auth_openidc

  augeas { 'Jenkins/useSecurity':
    incl => "/var/lib/jenkins/config.xml",
    lens => "Xml.lns",
    changes => "set hudson/useSecurity/#text ${use_security}",
  }

  augeas { 'Jenkins/authStrategy':
    incl => "/var/lib/jenkins/config.xml",
    lens => "Xml.lns",
    changes => "set hudson/authorizationStrategy/#attribute/class ${auth_strategy_class}",
  }

  $auth_matrix_permissions.each |Numeric $index, Hash $rule_hash| {
    augeas { "Jenkins/authMatrixPermission-${index+1}":
      incl => "/var/lib/jenkins/config.xml",
      lens => "Xml.lns",
      changes => "set hudson/authorizationStrategy/permission[${index+1}]/#text ${rule_hash['type']}:${rule_hash['action']}:${rule_hash['entity_name']}"
    }
  }

  augeas { 'Jenkins/securityRealm':
    incl => "/var/lib/jenkins/config.xml",
    lens => "Xml.lns",
    changes => "set hudson/securityRealm/#attribute/class ${security_realm_class}",
  }

  augeas { 'Jenkins/securityRealmPlugin':
    incl => "/var/lib/jenkins/config.xml",
    lens => "Xml.lns",
    changes => "set hudson/securityRealm/#attribute/plugin ${security_realm_plugin}",
  }

  $security_realm_settings.each |$key, $value| {
    augeas { "Jenkins/securityRealmSettings-${key}":
      incl => "/var/lib/jenkins/config.xml",
      lens => "Xml.lns",
      changes => "set hudson/securityRealm/${key}/#text ${value}"
    }
  }

}
