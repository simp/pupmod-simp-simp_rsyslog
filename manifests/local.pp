# **NOTE: THIS IS A [PRIVATE](https://github.com/puppetlabs/puppetlabs-stdlib#assert_private) CLASS**
#
# Set up local Rsyslog logging for the security relevant log files
#
# @param order
#   The shell-glob-based ordering for the rule
#
#   * This is currently set to not interfere with dynamic local rules and to
#     come before the standard 'ZZ' local SIMP default rules with some room to
#     grow.
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
class simp_rsyslog::local (
  String $order = 'HH'
){
  assert_private()

  rsyslog::rule::local { "${order}_simp_rsyslog_profile_local":
    rule            => $::simp_rsyslog::security_relevant_logs,
    target_log_file => $::simp_rsyslog::local_target,
    stop_processing => true
  }
}
