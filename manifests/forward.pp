# **NOTE: THIS IS A [PRIVATE](https://github.com/puppetlabs/puppetlabs-stdlib#assert_private) CLASS**
#
# Forward Rsyslog logs to remote servers
#
# @param order
#   The shell-glob-based ordering for the rule
#
# @param dest_type
#   The protocol to use when forwarding to the remote log server
#
#   * If you use ``tcp`` then you will need to adjust the ``TLS`` settings via
#     parameters in the ``::rsyslog`` class directly.
#
# @param stop_processing
#   Do not continue processing additional Rsyslog rules after the logs have
#   been sent to the remote server.
#
#   * In general, you will **not** want to have this set since you will not have
#     any of the matching logs written to local disk. However, this may be
#     appropriate for ephemeral systems, systems with very slow disks, or
#     systems where you want a minimum of log information to be captured
#     locally.
#
# @param permitted_peers
#   If TLS is being used, ``permitted_peers`` sets the StreamDriverPermittedPeers
#   directive in the forwarding rule actions for the remote rsyslog servers.
#   When ``undef``, the default value computed by
#   ``rsyslog::rule::remote::stream_driver_permitted_peers`` is used.
#
#   * You will need to set this value if any IP addresses appear in
#     ``simp_rsyslog::log_servers`` or ``simp_rsyslog::failover_servers`` AND
#     one or more of those servers is not in the same domain as the client.
#
#   * StreamDriverPermittedPeers is used to verify servers from the CN,
#     AltDNSname, or fingerprint of the certificate.
#
#   * Rsyslog expects a comma separated list. For example:
#     "*.my.domain,server1.my.other.domain"
#
#   @see https://www.rsyslog.com/doc/v8-stable/configuration/modules/omfwd.html
#   for more information on how to set this.
#
# @author https://github.com/simp/pupmod-simp-simp_rsyslog/graphs/contributors
#
class simp_rsyslog::forward (
  Integer                  $order           = 99,
  Enum['tcp','udp','relp'] $dest_type       = 'tcp',
  Boolean                  $stop_processing = false,
  Optional[String]         $permitted_peers = undef,
){
  assert_private()

  if empty($::simp_rsyslog::log_servers) {
    fail('You must specify ::simp_rsyslog::log_servers when attempting to forward logs')
  }

  if  $::simp_rsyslog::is_server and $::simp_rsyslog::enable_warning {
      warning("Possible log forwarding loop. Log forwarding is enable on a log server, ${facts['fqdn']}.  Make sure the log server and its aliases are not in the list of log servers, ${::simp_rsyslog::log_servers}, or fail over servers, ${::simp_rsyslog::failover_log_servers}.  To disable this message set ::simp_rsyslog::enable_warning to false for this server.")
  }

  rsyslog::rule::remote { "${order}_simp_rsyslog_profile_remote":
    rule                          => $::simp_rsyslog::security_relevant_logs,
    dest                          => $::simp_rsyslog::log_servers,
    failover_log_servers          => $::simp_rsyslog::failover_log_servers,
    dest_type                     => $dest_type,
    stream_driver_permitted_peers => $permitted_peers,
    stop_processing               => $stop_processing
  }
}
