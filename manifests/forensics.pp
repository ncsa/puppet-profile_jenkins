# @summary Jenkins controller JVM forensics: bounded evidence capture + fast-fail containment.
#
# Subclass of profile_jenkins (a namespaced class, NOT "inherits profile_jenkins":
# inheritance would auto-declare the parent and drag in its required parameters
# $use_security / $auth_strategy_class / $matrix_permissions / $security_realm_*).
#
# Inert by default: with $enabled = false this class declares no resources at all.
#
# Compatibility, verified against the two modules in use:
#
#   puppet/jenkins 3.3.0
#     * config_hash is NOT written to /etc/default/jenkins. jenkins::config.pp
#       only ensures plugins; jenkins::user_setup.pp renders config_hash through
#       systemd::dropin_file into /etc/systemd/system/jenkins.service.d/
#       puppet-overrides.conf as Environment="KEY=value" (templates/jenkins-override.epp).
#       The JVM flags therefore live in jenkins::config_hash, key JAVA_OPTS.
#     * That epp types its input as Hash[String, Struct[{value => Any}]], so every
#       config_hash value MUST be a hash with a 'value' key. A plain string is a
#       catalog compilation failure.
#     * The module manages only /etc/systemd/system/jenkins.service (removes it) and
#       the drop-in puppet-overrides.conf. Its service class is a bare
#       service { 'jenkins': } - it sets no Restart= and no TimeoutStopSec.
#
#   ncsa/profile_jenkins 1.2.0
#     * Uses include jenkins, so Hiera parameters are honoured (no resource-like
#       declaration that would override them).
#     * Has only init.pp and backup.pp; profile_jenkins::forensics is a new name.
#     * profile_jenkins::backup backs up ALL of /var/lib/jenkins. Heap dumps must
#       therefore NOT live there, which is why $root defaults to /var/log.
#
# @param enabled               Master switch. False = no resources, no changes.
# @param purge_on_disable      When $enabled is false, stand the machinery down.
# @param root                  Evidence directory. Must be on the volume with room for
#                              a full heap dump (~30 GiB raw, ~5 GiB gzipped), and must
#                              NOT be under /var/lib/jenkins (the backup job sweeps it)
#                              nor on the root filesystem (3.6 GB free on this host).
# @param user                  User the Jenkins JVM runs as (jcmd attach needs same UID).
# @param group                 Group for the evidence directories and the sampler unit.
# @param jcmd                  jcmd binary; resolved from /proc/<pid>/exe when available.
# @param gc_log_dir            Directory for -Xlog:gc* output (same volume as $root).
# @param min_free_mb           Refuse to start a VOLUNTARY heap dump below this much free
#                              space. Sized for raw dump + gzip output simultaneously.
# @param keep_heap_dumps       How many .hprof/.hprof.gz to keep.
# @param keep_incidents        How many incident bundles to keep.
# @param thread_percent        Heap % at which one thread dump + fd/ssh counters are taken.
# @param histogram_percent     Heap % at which one live class histogram is taken (full GC).
# @param histogram_max_percent Never take that histogram above this % (it forces a full GC).
# @param jfr_percent           Heap % at which the flight recording is dumped.
# @param heap_dump_percent     Heap % at which to dump while alive. 0 disables.
# @param jfr_name              Flight recording name (must match -XX:StartFlightRecording).
# @param interval              Sampler period, systemd time span syntax (5min, 1h).
# @param manage_dropin         Manage the jenkins.service drop-in (Restart, Exec hooks).
class profile_jenkins::forensics (
  Boolean $enabled               = false,
  Boolean $purge_on_disable      = false,
  String  $root                  = '/u/jenkins-forensics',
  String  $user                  = 'jenkins',
  String  $group                 = 'jenkins',
  String  $jcmd                  = 'jcmd',
  String  $gc_log_dir            = '/u/jenkins-forensics/gc',
  Integer $min_free_mb           = 35840,
  Integer $keep_heap_dumps       = 2,
  Integer $keep_incidents        = 20,
  Integer $thread_percent        = 70,
  Integer $histogram_percent     = 80,
  Integer $histogram_max_percent = 92,
  Integer $jfr_percent           = 88,
  Integer $heap_dump_percent     = 0,
  String  $jfr_name              = 'jenkins',
  String  $interval              = '5min',
  Boolean $manage_dropin         = true,
) {
  # Best-effort lint against the half-on state. The flags are jenkins module data
  # (jenkins::config_hash -> systemd drop-in Environment), so this class cannot
  # gate them; all it can do is say so loudly. getvar returns undef if the jenkins
  # class has not been evaluated yet - then we stay quiet rather than guess.
  $config = getvar('jenkins::config_hash')
  if is_hash($config) {
    $java_opts = $config['JAVA_OPTS']
    if is_hash($java_opts) and is_string($java_opts['value']) {
      $flags = $java_opts['value']
      if $enabled and $flags !~ /ExitOnOutOfMemoryError/ {
        warning('JAVA_OPTS has no -XX:+ExitOnOutOfMemoryError: the controller keeps thrashing instead of exiting and restarting')
      } elsif !$enabled and $flags =~ /jenkins-oom-hook/ {
        warning('JAVA_OPTS references the forensics OOM hook but profile_jenkins::forensics::enabled is false')
      }
    } elsif $enabled {
      warning('JAVA_OPTS missing or not shaped as {"value" => "<flags>"}: puppet/jenkins 3.3.0 needs that shape or no flag reaches the JVM')
    }
  }

  if $enabled {
    # $root must sit on a real, roomy filesystem: the JVM writes a ~30 GiB dump
    # there at OOM. This host keeps nearly all storage under /var/lib/jenkins and
    # /u, with ~3.6 GB left on the root filesystem, so a fallback to "/" would
    # fill the host. Fail loudly in the catalog rather than at 3 a.m.
    $mountpoints = $facts['mountpoints']
    if $mountpoints =~ Hash {
      $other_mounts = $mountpoints.keys.filter |$m| { $m != '/' }
      $mount_list   = join($other_mounts, ', ')
      $mount_alt    = join($other_mounts, '|')
      $mount_re     = "^(${mount_alt})(/|$)"
      if $other_mounts.length == 0 {
        warning("only the root filesystem is mounted; ${root} needs a dedicated volume, a 30 GiB dump would fill /")
      } elsif $root !~ $mount_re {
        warning("${root} is not on a dedicated mount (have: ${mount_list}); the next heap dump could fill /")
      }
    }

    $dirs = [
      $root,
      "${root}/jfr",
      "${root}/incidents",
      "${root}/state",
      $gc_log_dir,
    ]

    file { $dirs:
      ensure => directory,
      owner  => $user,
      group  => $group,
      mode   => '0750',
    }

    # Single source of truth for the shell side, driven from Hiera.
    $conf = [
      '# Managed by profile_jenkins::forensics - do not edit',
      '# shellcheck shell=bash',
      "FORENSICS_ROOT=${root}",
      "GC_LOG_DIR=${gc_log_dir}",
      "JENKINS_USER=${user}",
      "JENKINS_GROUP=${group}",
      "JCMD=${jcmd}",
      "JFR_NAME=${jfr_name}",
      "MIN_FREE_MB=${min_free_mb}",
      "KEEP_HEAP_DUMPS=${keep_heap_dumps}",
      "KEEP_INCIDENTS=${keep_incidents}",
      "THREAD_PERCENT=${thread_percent}",
      "HISTOGRAM_PERCENT=${histogram_percent}",
      "HISTOGRAM_MAX_PERCENT=${histogram_max_percent}",
      "JFR_PERCENT=${jfr_percent}",
      "HEAP_DUMP_PERCENT=${heap_dump_percent}",
    ].join("\n")

    file { '/etc/jenkins-forensics.conf':
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => "${conf}\n",
      notify  => Exec['jenkins-forensics-daemon-reload'],
    }

    file { '/usr/local/sbin/jenkins-forensics.sh':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0755',
      source => 'puppet:///modules/profile_jenkins/jenkins-forensics.sh',
    }

    file { '/usr/local/sbin/jenkins-postmortem.sh':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0755',
      source => 'puppet:///modules/profile_jenkins/jenkins-postmortem.sh',
    }

    file { '/usr/local/sbin/jenkins-oom-hook.sh':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0755',
      source => 'puppet:///modules/profile_jenkins/jenkins-oom-hook.sh',
    }

    file { '/usr/local/sbin/jenkins-histogram-diff.sh':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0755',
      source => 'puppet:///modules/profile_jenkins/jenkins-histogram-diff.sh',
    }

    $unit_service = [
      '[Unit]',
      'Description=Jenkins controller JVM forensics sampler',
      'After=jenkins.service',
      '',
      '[Service]',
      'Type=oneshot',
      "User=${user}",
      "Group=${group}",
      'Nice=10',
      'IOSchedulingClass=idle',
      'ExecStart=/usr/local/sbin/jenkins-forensics.sh',
      '',
    ].join("\n")

    $unit_timer = [
      '[Unit]',
      'Description=Periodic JVM forensics sampling for the Jenkins controller',
      '',
      '[Timer]',
      "OnBootSec=${interval}",
      "OnUnitActiveSec=${interval}",
      'AccuracySec=30s',
      'Persistent=false',
      'Unit=jenkins-forensics.service',
      '',
      '[Install]',
      'WantedBy=timers.target',
      '',
    ].join("\n")

    file { '/etc/systemd/system/jenkins-forensics.service':
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => $unit_service,
      notify  => Exec['jenkins-forensics-daemon-reload'],
    }

    file { '/etc/systemd/system/jenkins-forensics.timer':
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => $unit_timer,
      notify  => Exec['jenkins-forensics-daemon-reload'],
    }

    exec { 'jenkins-forensics-daemon-reload':
      command     => 'systemctl daemon-reload',
      path        => ['/usr/bin', '/bin', '/usr/sbin', '/sbin'],
      refreshonly => true,
    }

    service { 'jenkins-forensics.timer':
      ensure  => running,
      enable  => true,
      require => [
        File['/etc/systemd/system/jenkins-forensics.service'],
        File['/etc/systemd/system/jenkins-forensics.timer'],
        Exec['jenkins-forensics-daemon-reload'],
      ],
    }

    # Backstop retention: the scripts prune by count, tmpfiles prunes by age in
    # case the sampler never runs again (e.g. jenkins stuck in a crash loop).
    $tmpfiles = [
      "d ${root} 0750 ${user} ${group} -",
      "d ${root}/jfr 0750 ${user} ${group} -",
      "D ${root}/incidents 0750 ${user} ${group} 14d",
      "D ${root}/state 0750 ${user} ${group} 3d",
      "d ${gc_log_dir} 0750 ${user} ${group} -",
      "D ${gc_log_dir} 0750 ${user} ${group} 7d",
    ].join("\n")

    file { '/etc/tmpfiles.d/jenkins-forensics.conf':
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => "${tmpfiles}\n",
    }

    if $manage_dropin {
      # zz- sorts AFTER puppet-overrides.conf (written by jenkins::user_setup via
      # systemd::dropin_file), so these scalar directives win deterministically.
      # That file carries only Environment= lines, so the only overlap risk is if
      # someone later puts Restart=/TimeoutStopSec= into jenkins::service_override.
      $evidence_dirs = "${root} ${root}/jfr ${gc_log_dir}"

      $dropin = [
        '# Managed by profile_jenkins::forensics',
        '[Unit]',
        '# A crash loop must not pin a 4 vCPU box: at most 12 starts per 30 minutes,',
        '# after which the unit stays failed and is visible in systemctl status.',
        '# Clear with: systemctl reset-failed jenkins',
        'StartLimitIntervalSec=1800',
        'StartLimitBurst=12',
        '# The JVM writes the heap dump, the live JFR repository and the GC log to',
        '# these paths. Ordering on their backing mount means ExecStartPre cannot',
        '# create the directory on a root filesystem that still has 3.6 GB free and',
        '# then take a 28 GiB dump there when the volume is late.',
        "RequiresMountsFor=${root} ${gc_log_dir}",
        '',
        '[Service]',
        '# -XX:+ExitOnOutOfMemoryError terminates the JVM with a non-zero status (3),',
        '# which is exactly what on-failure reacts to; SIGSEGV/SIGABRT (hs_err) are',
        '# covered too, since no such signal is listed in SuccessExitStatus. A',
        '# deliberate "systemctl stop" is never restarted, and puppet-driven',
        '# restarts (jenkins::service hasrestart) behave as before.',
        'Restart=on-failure',
        'RestartSec=15',
        '',
        '# A normal SIGTERM stop takes ~1s; 40s bounds the wedged case (previously',
        '# the full 90s systemd default, then SIGKILL).',
        'TimeoutStopSec=40',
        '',
        '# Guarantee the dump/JFR/GC-log targets exist before the JVM starts. "-"',
        '# keeps a directory problem from blocking start-up.',
        "ExecStartPre=-+/usr/bin/install -d -m 0750 -o ${user} -g ${group} ${evidence_dirs}",
        '',
        '# "-" so a broken postmortem can never mark the unit failed or delay the',
        '# restart; "+" so journalctl -u jenkins works without adding jenkins to',
        '# systemd-journal.',
        'ExecStopPost=-+/usr/local/sbin/jenkins-postmortem.sh',
        '',
      ].join("\n")

      # Do NOT declare /etc/systemd/system/jenkins.service.d here:
      # systemd::dropin_file, which jenkins::user_setup uses for
      # puppet-overrides.conf, declares that directory itself, and two
      # resource-like declarations of one File title always collide whatever
      # the attributes are. install -d only runs when the directory is absent,
      # so whichever class compiles first, the other still succeeds (Puppet's
      # file type does not create missing parents).
      exec { 'jenkins-forensics-dropin-dir':
        command => 'install -d -m 0755 -o root -g root /etc/systemd/system/jenkins.service.d',
        creates => '/etc/systemd/system/jenkins.service.d',
        path    => ['/usr/bin', '/bin'],
        before  => File['/etc/systemd/system/jenkins.service.d/zz-forensics.conf'],
      }

      file { '/etc/systemd/system/jenkins.service.d/zz-forensics.conf':
        ensure  => file,
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
        content => $dropin,
        notify  => Exec['jenkins-forensics-daemon-reload'],
      }
    }
  } elsif $purge_on_disable {
    # Explicit stand-down: stop the sampler and remove what this class installed.
    # Evidence under $root is deliberately left alone - never delete findings -
    # which also keeps the -Xlog/HeapDumpPath/JFR targets valid until the
    # JAVA_OPTS block is reverted in Hiera.
    $purge_files = [
      '/etc/systemd/system/jenkins-forensics.service',
      '/etc/systemd/system/jenkins-forensics.timer',
      '/etc/systemd/system/jenkins.service.d/zz-forensics.conf',
      '/etc/jenkins-forensics.conf',
      '/etc/tmpfiles.d/jenkins-forensics.conf',
      '/usr/local/sbin/jenkins-forensics.sh',
      '/usr/local/sbin/jenkins-postmortem.sh',
      '/usr/local/sbin/jenkins-oom-hook.sh',
      '/usr/local/sbin/jenkins-histogram-diff.sh',
    ]

    # before => so "systemctl disable --now" still finds the timer unit file.
    exec { 'jenkins-forensics-standdown':
      command => 'systemctl disable --now jenkins-forensics.timer',
      onlyif  => 'systemctl is-enabled jenkins-forensics.timer >/dev/null 2>&1',
      path    => ['/usr/bin', '/bin'],
      before  => File[$purge_files],
    }

    file { $purge_files:
      ensure => absent,
      notify => Exec['jenkins-forensics-standdown-reload'],
    }

    exec { 'jenkins-forensics-standdown-reload':
      command     => 'systemctl daemon-reload',
      path        => ['/usr/bin', '/bin'],
      refreshonly => true,
      require     => Exec['jenkins-forensics-standdown'],
    }
  } else {
    notice('profile_jenkins::forensics is disabled (profile_jenkins::forensics::enabled: false) - managing nothing')
  }
}
