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
#   If TLS is being used, StreamDriverPermittedPeers is used to check the certificates.
#   permitted_peers is used to set this.  In general, certificates will use the FQDN
#   of the host as the CN in the subject of the certificate.  The default, "LOGSERVERNAME"  assumes that
#   $::simp_rsyslog::log_servers and  $::simp_rsyslog::failover_log_servers are a list
#   of FQDNs and that certificates used by the log servers to encrypt traffic use this for the CN.
#   If this is not the case, then you will need to set this variable appropriately.
#   Example:  If IP Addresses are used in the two simp_rsyslog settings above and the CN in 
#   the servers certs are server.my.domain and server2,my.other.domain: 
#   Set this to "server.my.domain,server2.my.other.domain"
#   @see https://www.rsyslog.com/doc/v8-stable/configuration/modules/omfwd.html
#   for more information on how to set this.
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
class simp_rsyslog::forward (
  Integer                  $order            = 99,
  Enum['tcp','udp','relp'] $dest_type        = 'tcp',
  Boolean                  $stop_processing  = false,
  String                   $permitted_peers  = 'LOGSERVERNAME'
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
