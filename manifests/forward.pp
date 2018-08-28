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
#   If TLS is being used, permitted_peers sets StreamDriverPermittedPeers in the rsyslog rule.
#   THis is used to verify servers from the CN, AltDNSname, or fingerprint of certificate.
#   If permitted peers is undef and TLS is being used it will default to the names
#   in the log_server and failover_log_server parameters after checking if the
#   values used in these arrays are hostnames and not IP Addresses.
#   Set permitted_peers to a valid string if you need to use IP Addresses.
#   (It uses a string which is a comma seperated list of values.  Hostnames can have
#   a wild card as the first part.)  Example "*.my.domain,logserver555.that.other.domain"
#   @see https://www.rsyslog.com/doc/v8-stable/configuration/modules/omfwd.html
#   for more information on how to set this.
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
class simp_rsyslog::forward (
  Integer                  $order           = 99,
  Enum['tcp','udp','relp'] $dest_type       = 'tcp',
  Boolean                  $stop_processing = false,
  Optional[Array[String]]  $permitted_peers = undef,
  Boolean                  $enable_tls      = simplib::lookup('rsyslog::enable_tls_logging', {'default_value' => false }),
){
  assert_private()

  if empty($::simp_rsyslog::log_servers) {
    fail('You must specify ::simp_rsyslog::log_servers when attempting to forward logs')
  }

  if  $::simp_rsyslog::is_server and $::simp_rsyslog::enable_warning {
      warning("Possible log forwarding loop. Log forwarding is enable on a log server, ${facts['fqdn']}.  Make sure the log server and its aliases are not in the list of log servers, ${::simp_rsyslog::log_servers}, or fail over servers, ${::simp_rsyslog::failover_log_servers}.  To disable this message set ::simp_rsyslog::enable_warning to false for this server.")
  }

  if $permitted_peers {
    $_permitted_peers = join($permitted_peers, ',' )
  } else {
    if $enable_tls {
      # If permitted peers is not defined and TLS is enabled the names of the log servers are used to
      # as the permitted peers.   So we check to make sure IP Adddresses are not being used.
      $::simp_rsyslog::log_servers.each | $d | {
        assert_type(Variant[Simplib::Hostname,Simplib::Hostname::Port], $d ) | $x, $y | {
          fail("If using TLS and permitted_peers is set empty, then you must use a hostname for log_servers. ${d} is not a hostname. Either set permitted peers to a list of valid entries or use FQDN in simp_rsyslog::log_servers")
          }
      }
      if empty($::simp_rsyslog::failover_log_servers) {
        $_permitted_peers = join($::simp_rsyslog::log_servers, ',')
      } else {
        $::simp_rsyslog::failover_log_servers.each | $f | {
          assert_type(Variant[Simplib::Hostname,Simplib::Hostname::Port], $f ) | $x, $y | {
            fail("If using TLS and permitted_peers is set empty, then you must use a hostname for failover logservers. ${f} is not a hostname. Either set permitted_peers to a list of valid entries or use FQDN in simp_rsyslog::log_servers")
          }
        }
        $_permitted_peers = join( [ join($::simp_rsyslog::log_servers, ',') , join($::simp_rsyslog::failover_log_servers, ',') ], ',')
      }
    #No TLS set so use
    }  else {
      $_permitted_peers =  undef
    }
  }

  rsyslog::rule::remote { "${order}_simp_rsyslog_profile_remote":
    rule                          => $::simp_rsyslog::security_relevant_logs,
    dest                          => $::simp_rsyslog::log_servers,
    failover_log_servers          => $::simp_rsyslog::failover_log_servers,
    dest_type                     => $dest_type,
    stream_driver_permitted_peers => $_permitted_peers,
    stop_processing               => $stop_processing
  }
}
