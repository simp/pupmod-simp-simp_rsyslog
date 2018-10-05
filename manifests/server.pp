# **NOTE: THIS IS A [PRIVATE](https://github.com/puppetlabs/puppetlabs-stdlib#assert_private) CLASS**
#
# This class provides a general purpose log server suitable for centralized
# logging.
#
# It is **highly** recommended that you look to use the Logstash module at this
# point.
#
# The following must be set in Hiera for this class to work properly:
#
# ```
# rsyslog::global::tls_tcpserver: true
#
# The following are optional for legacy, unencrypted connections.
# rsyslog::global::tcpserver: true
# rsyslog::global::udpserver: true
# rsyslog::global::udpServerAddress: '0.0.0.0'
# ```
#
# ------------------------------------------------------------------------
#
# Loose standard for the rules that will be created:
#
# * 10_default = specific rules to be caught early (ex. matching on programname +
#               error + etc.)
# * 11_default = specific rules that have a corresponding "0_default" entry but
#               have a less-specific rule than "0_default" (ex. matching on programname)
# * 17_default = catch all for security relevant logs that weren't caught by previous rules
# * 19_default = anything else gets sent to messages
# * 30_default = stop processing (if appropriate), don't go past this
#
# ------------------------------------------------------------------------
#
# @param server_conf
#   The full configuration to use
#
#   * Adds the contained rsyslog configuration to the system
#     instead of the default from this module. This allows you complete freedom
#     in specifying your log server ruleset if you do not like the one that is
#     provided. There will be **no** sanity checking of this string!
#
# @param process_sudosh_rules
#   Enable processing of sudosh rules
#
# @param process_tlog_rules
#   Enable processing of tlog rules
#
# @param process_httpd_rules
#   Enable processing of httpd rules
#
# @param process_dhcpd_rules
#   Enable processing of dhcpd rules
#
# @param process_snmpd_rules
#   Enable processing of snmpd rules
#
# @param process_puppet_agent_rules
#   Enable processing of puppet agent rules
#
# @param process_puppetserver_rules
#   Enable processing of puppetserver rules
#
# @param process_auditd_rules
#   Enable processing of auditd rules
#
# @param process_aide_rules
#   Enable processing of aide rules
#
# @param process_slapd_rules
#   Enable processing of OpenLDAP Server rules
#
# @param process_kern_rules
#   Enable processing of kern.* rules
#
# @param process_iptables_rules
#   Enable processing of messages starting with ``IPT:``
#
# @param process_security_relevant_logs
#   Enable processing of the ``::simp_rsyslog::security_relevant_logs``
#
# @param process_message_rules
#   Enable the default ``/var/log/message`` traditional processing
#
# @param process_mail_rules
#   Enable processing of mail.* rules
#
# @param process_cron_rules
#   Enable processing of cron.* rules
#
# @param process_emerg_rules
#   Enable processing of *.emerg rules
#
# @param process_spool_rules
#   Enable processing of spool.* rules
#
# @param process_boot_rules
#   Enable processing of local7.* rules
#
# @param enable_catchall
#   Add anything missed by other rules to a ``catchall.log`` file
#
# @param stop_processing
#   Do not continue processing additional Rsyslog rules after the logs have
#   been sent to the remote server.
#
#   * You will probably want to keep this set so that your local system logs
#     are not filled with material from other hosts.
#
# @param add_logrotate_rule
#   Add a logrotate rule for the logs that are collected by these server rules
#
#   * This will **not** be applied if you are not using the inbuilt rules since
#     there is no way to know what you are doing.
#
# @param rotate_period
#   How often to rotate the local logs
#
#   * Has no effect if ``add_logrotate_rule`` is ``false``
#
# @param rotate_preserve
#   How many rotated logs to preserve
#
#   * 3 months by default
#
#   * Has no effect if ``add_logrotate_rule`` is ``false``
#
# @param rotate_size
#   The maximum size of a log file
#
#   * ``$rotate_period`` will be ignored if this is specified
#
#   * Has no effect if ``add_logrotate_rule`` is ``false``
#
# @param logdir
#   The directory where the server will send collected logs
#
# @param dyna_key
#   The dyna_file rule that organizes the logs as they come in
#
#   @see https://www.rsyslog.com/doc/v8-stable/configuration/templates.html
#   @see https://www.rsyslog.com/doc/v8-stable/configuration/properties.html
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
class simp_rsyslog::server (
  Optional[String]                          $server_conf                    = undef,
  Boolean                                   $process_sudosh_rules           = true,
  Boolean                                   $process_tlog_rules             = true,
  Boolean                                   $process_httpd_rules            = true,
  Boolean                                   $process_dhcpd_rules            = true,
  Boolean                                   $process_snmpd_rules            = true,
  Boolean                                   $process_puppet_agent_rules     = true,
  Boolean                                   $process_puppetserver_rules     = true,
  Boolean                                   $process_auditd_rules           = true,
  Boolean                                   $process_aide_rules             = true,
  Boolean                                   $process_slapd_rules            = true,
  Boolean                                   $process_kern_rules             = true,
  Boolean                                   $process_iptables_rules         = true,
  Boolean                                   $process_security_relevant_logs = true,
  Boolean                                   $process_message_rules          = true,
  Boolean                                   $process_mail_rules             = true,
  Boolean                                   $process_cron_rules             = true,
  Boolean                                   $process_emerg_rules            = true,
  Boolean                                   $process_spool_rules            = true,
  Boolean                                   $process_boot_rules             = true,
  Boolean                                   $enable_catchall                = true,
  Boolean                                   $stop_processing                = true,
  Boolean                                   $add_logrotate_rule             = true,
  Enum['daily','weekly','monthly','yearly'] $rotate_period                  = 'weekly',
  Integer                                   $rotate_preserve                = 12,
  Optional[Integer]                         $rotate_size                    = undef,
  Stdlib::AbsolutePath                      $logdir                         = '/var/log/hosts',
  String                                    $dyna_key                       = '%HOSTNAME%'
) {
  assert_private()

  include '::rsyslog'
  include '::rsyslog::server'

  if $server_conf {
    rsyslog::rule::drop { '0_default':
      rule => $server_conf
    }
  }
  else {
    $file_base = "${logdir}/${dyna_key}"

    # Up front because they are the fastest to process
    if $process_boot_rules {
      rsyslog::rule::local { '10_00_default_boot':
        rule            => 'prifilt(\'local7.*\')',
        dyna_file       => "${file_base}/boot.log",
        stop_processing => $stop_processing
      }
    }
    if $process_mail_rules {
      rsyslog::rule::local { '10_00_default_mail':
        rule            => 'prifilt(\'mail.*\')',
        dyna_file       => "${file_base}/mail.log",
        stop_processing => $stop_processing
      }
    }
    if $process_cron_rules {
      rsyslog::rule::local { '10_00_default_cron':
        rule            => 'prifilt(\'cron.*\')',
        dyna_file       => "${file_base}/cron.log",
        stop_processing => $stop_processing
      }
    }
    if $process_emerg_rules {
      rsyslog::rule::local { '10_00_default_emerg':
        rule            => 'prifilt(\'*.emerg\')',
        dyna_file       => "${file_base}/emergency.log",
        stop_processing => $stop_processing
      }
    }

    # Every other regular processing rule
    if $process_sudosh_rules {
      rsyslog::rule::local { '10_default_sudosh':
        rule            => '$programname == \'sudosh\'',
        dyna_file       => "${file_base}/sudosh.log",
        stop_processing => $stop_processing
      }
    }
    if $process_tlog_rules {
      rsyslog::rule::local { '10_default_tlog':
        rule            => '$programname == \'tlog-rec-session\' or $programname == \'-tlog-rec-session\' or $programname == \'tlog\'',
        dyna_file       => "${file_base}/tlog.log",
        stop_processing => $stop_processing
      }
    }
    if $process_httpd_rules {
      rsyslog::rule::local { '10_default_httpd_error':
        rule            => 'prifilt(\'*.err\') and ($programname == \'httpd\')',
        dyna_file       => "${file_base}/httpd_error.log",
        stop_processing => $stop_processing
      }
      rsyslog::rule::local { '11_default_httpd':
        rule            => '$programname == \'httpd\'',
        dyna_file       => "${file_base}/httpd.log",
        stop_processing => $stop_processing
      }
    }
    if $process_dhcpd_rules {
      rsyslog::rule::local { '10_default_dhcpd':
        rule            => '$programname == \'dhcpd\'',
        dyna_file       => "${file_base}/dhcpd.log",
        stop_processing => $stop_processing
      }
    }
    if $process_snmpd_rules {
      rsyslog::rule::local { '10_default_snmpd':
        rule            => '$programname == \'snmpd\'',
        dyna_file       => "${file_base}/snmpd.log",
        stop_processing => $stop_processing
      }
    }
    if $process_puppet_agent_rules {
      rsyslog::rule::local { '10_default_puppet_agent_error':
        rule            => 'prifilt(\'*.err\') and ($programname == \'puppet-agent\')',
        dyna_file       => "${file_base}/puppet_agent_error.log",
        stop_processing => $stop_processing
      }
      rsyslog::rule::local { '11_default_puppet_agent':
        rule            => '$programname == \'puppet-agent\'',
        dyna_file       => "${file_base}/puppet_agent.log",
        stop_processing => $stop_processing
      }
    }
    if $process_puppetserver_rules {
      rsyslog::rule::local { '10_default_puppetserver_error':
        rule            => 'prifilt(\'*.err\') and ($programname == \'puppetserver\')',
        dyna_file       => "${file_base}/puppetserver_error.log",
        stop_processing => $stop_processing
      }
      rsyslog::rule::local { '11_default_puppetserver':
        rule            => '$programname == \'puppetserver\'',
        dyna_file       => "${file_base}/puppetserver.log",
        stop_processing => $stop_processing
      }
    }
    if $process_auditd_rules {
      rsyslog::rule::local { '10_default_audit':
        rule            => '($programname == \'audispd\') or ($syslogtag == \'tag_auditd_log:\')',
        dyna_file       => "${file_base}/auditd.log",
        stop_processing => $stop_processing
      }
    }
    if $process_aide_rules {
      rsyslog::rule::local { '10_default_aide':
        rule            => '$programname == \'aide\'',
        dyna_file       => "${file_base}/aide.log",
        stop_processing => $stop_processing
      }
    }
    if $process_slapd_rules {
      rsyslog::rule::local { '10_default_slapd_audit':
        rule            => '$programname == \'slapd_audit\'',
        dyna_file       => "${file_base}/slapd_audit.log",
        stop_processing => $stop_processing
      }
    }
    if $process_iptables_rules {
      rsyslog::rule::local { '10_default_iptables':
        # Some versions of rsyslog include the space separator that precedes
        # the message as part of the message body
        rule            => 'prifilt(\'kern.*\') and (($msg startswith \' IPT:\') or ($msg startswith \'IPT:\'))',
        dyna_file       => "${file_base}/iptables.log",
        stop_processing => $stop_processing
      }
    }
    if $process_kern_rules {
      rsyslog::rule::local { '10_default_kern':
        rule            => 'prifilt(\'kern.*\')',
        dyna_file       => "${file_base}/kernel.log",
        stop_processing => $stop_processing
      }
    }
    if $process_spool_rules {
      rsyslog::rule::local { '10_default_spool':
        rule            => '($syslogfacility-text == \'uucp\') or (($syslogfacility-text == \'news\') and prifilt(\'*.crit\'))',
        dyna_file       => "${file_base}/spool.log",
        stop_processing => $stop_processing
      }
    }

    # Late processing items
    if $process_security_relevant_logs {
      rsyslog::rule::local { '17_default_security_relevant_logs':
        rule            => $::simp_rsyslog::security_relevant_logs,
        dyna_file       => "${file_base}/secure.log",
        stop_processing => $stop_processing
      }
    }
    if $process_message_rules {
      rsyslog::rule::local { '19_default_message':
        rule            => 'prifilt(\'*.info;mail.none;authpriv.none;cron.none;local6.none;local5.none\')',
        dyna_file       => "${file_base}/messages.log",
        stop_processing => $stop_processing
      }
    }

    # End of processing
    if $enable_catchall {
      rsyslog::rule::local { '30_default_catchall':
        rule            => 'prifilt(\'*.*\')',
        dyna_file       => "${file_base}/catchall.log",
        stop_processing => $stop_processing
      }
    }
    else {
      if $stop_processing {
        rsyslog::rule::local { '30_default_drop':
          rule            => 'prifilt(\'*.*\')',
          dyna_file       => '~',
          # We don't need this due to the line above
          stop_processing => false
        }
      }
    }

    if $add_logrotate_rule {
      include '::logrotate'

      logrotate::rule { 'simp_rsyslog_server_profile':
        log_files                 => [ "${logdir}/*/*.log" ],
        missingok                 => true,
        size                      => $rotate_size,
        rotate_period             => $rotate_period,
        rotate                    => $rotate_preserve,
        lastaction_restart_logger => true
      }
    }
  }
}
