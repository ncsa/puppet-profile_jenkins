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
# @param auth_strategy
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
  String $auth_strategy,
  Optional[Array[Hash]] $auth_matrix_permissions,
  String $security_realm_class,
  Optional[String] $security_realm_plugin,
  Hash $security_realm_settings,
){

  include ::java
  include ::jenkins
  include ::apache::mod::auth_openidc

  # Enable and install module stream on RHEL 8.x
#  if $facts['os']['family'] == 'RedHat' and $facts['os']['release']['major'] == '8' {
#    package { 'mod_auth_openidc-module':
#      name => 'mod_auth_openidc',
#      ensure => present,
#      enable_only => true,
#      provider => dnfmodule,
#    }

#    package { 'mod_auth_openidc':
#      ensure => installed,
#      provider => dnf,
#      require => Package['mod_auth_openidc-module'],
#    }
#  }

  file { '/var/lib/jenkins/config.xml':
    ensure => file,
    content => epp('profile_jenkins/config.xml.epp'),
    owner => 'jenkins',
    group => 'jenkins',
    mode => '0644',
    require => Package['jenkins'],
  }

}
