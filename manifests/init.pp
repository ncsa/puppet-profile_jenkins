# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include profile_jenkins
class profile_jenkins (
  Boolean $use_security,
  String $auth_strategy,
  Optional[Hash[Hash]] $auth_matrix_permissions,
  String $security_realm_class,
  Optional[String] $security_realm_plugin,
  Hash $security_realm_settings,
){

  include ::java
  include ::jenkins
  include ::apache::mod::auth_openidc

  # Enable and install module stream on RHEL 8.x
  if $facts['os']['family'] == 'RedHat' and $facts['os']['release']['major'] == '8' {
    package { 'mod_auth_openidc-module':
      name => 'mod_auth_openidc',
      ensure => present,
      enable_only => true,
      provider => dnfmodule,
    }

    package { 'mod_auth_openidc':
      ensure => installed,
      provider => dnf,
      require => Package['mod_auth_openidc-module'],
    }
  }

  file { '/var/lib/jenkins/config.xml':
    ensure => file,
    content => epp('profile_jenkins/config.xml.epp'),
    owner => 'jenkins',
    group => 'jenkins',
    mode => '0644',
    require => Package['jenkins'],
  }

}
