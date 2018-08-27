# **NOTE: THIS IS A [PRIVATE](https://github.com/puppetlabs/puppetlabs-stdlib#assert_private) CLASS**
#
# Set up local Rsyslog logging for the security relevant log files
#
# @param order
#   The shell-glob-based ordering for the rule
#
#   This is currently set to ensure the following:
#   * Comes after the dynamic local rules that would be on a Rsyslog server
#     (1* and 3* rules from simp_rsyslog::server)
#   * Comes after the SIMP-module-specific rules that would be on a Rsyslog
#     client (XX_* and YY_* rules from the sudosh, apache etc. modules).
#   * Comes before the standard 'ZZ_default.conf' file from SIMP's rsyslog
#     module.
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
class simp_rsyslog::local (
  String $order = 'ZZ_0'
){
  assert_private()

  # Since there already are local audispd audit logs in /var/log/audit and these
  # logs grow quickly, drop the syslog duplicates.
  $_safe_order = regsubst($order,'/','__')
  rsyslog::rule::local {"${_safe_order}1_simp_rsyslog_profile_local_drop_audispd_duplicates":
    content => "if (\$programname == \'audispd\') then stop\n"
  }

  # All other security logs which will NOT be handled by the 'ZZ_default' rules.
  # (ZZ_default contains iptables, puppet-agent, puppetserver and
  # local6.* rules, in the appropriate order.)
  #
  # TODO
  # 1. Write a rule that allows *.emerg messages to both log to the console
  #    of all users and to be persisted to file.
  $_residual_logs = {
    'programs'   => [
      'audispd',
      'audit',
      'auditd',
      'crond',
      'sudo',
      'systemd',
      'yum'
    ],

    'facilities' => [
      '*.emerg',
      'local7.warn'
    ],
  }

  $residual_security_logs = simp_rsyslog::format_options($_residual_logs)
  rsyslog::rule::local { "${order}2_simp_rsyslog_profile_local_security":
    rule            => $residual_security_logs,
    target_log_file => $::simp_rsyslog::local_target,
    stop_processing => true
  }
}
