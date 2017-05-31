require 'spec_helper_acceptance'

test_name 'simp_rsyslog profile'

describe 'simp_rsyslog' do
  before(:context) do
    hosts.each do |host|
      interfaces = fact_on(host, 'interfaces').strip.split(',')
      interfaces.delete_if do |x|
        x =~ /^lo/
      end

      interfaces.each do |iface|
        if fact_on(host, "ipaddress_#{iface}").strip.empty?
          on(host, "ifup #{iface}", :accept_all_exit_codes => true)
        end
      end
    end
  end

  hosts_with_role( hosts, 'rsyslog_server' ).each do |server|
    hosts_with_role(hosts, 'rsyslog_client').each do |client|
      context "#{client} logging to the remote syslog server #{server} with default forwarding" do
        let(:client_fqdn){ fact_on( client, 'fqdn' ) }
        let(:server_fqdn){ fact_on( server, 'fqdn' ) }
        let(:manifest) { <<-EOS
include 'simp_rsyslog'
EOS
        }
        let(:client_hieradata) {
    <<-EOS
---
simp_options::syslog::log_servers:
  - '#{server_fqdn}'

simp_rsyslog::forward_logs: true
rsyslog::pki: false
rsyslog::enable_tls_logging: false

EOS
        }

        let(:server_hieradata) {
    <<-EOS
---
simp_options::syslog::log_servers:
  - '#{server_fqdn}'

simp_rsyslog::is_server: true
simp_rsyslog::forward_logs: false
rsyslog::tcp_server: true
rsyslog::tls_tcp_server: false
rsyslog::pki: false
EOS
        }

        let(:client_log_dir) { "/var/log/hosts/#{client_fqdn}" }

        it "should configure server #{server} without errors" do
          set_hieradata_on(server, server_hieradata)
          apply_manifest_on(server, manifest, :catch_failures => true)
        end

        it "should configure #{server} idempotently" do
          apply_manifest_on(server, manifest, :catch_changes => true)
        end

        it "should configure client #{client} without errors" do
          set_hieradata_on(client, client_hieradata)
          apply_manifest_on(client, manifest, :catch_failures => true)
        end

        it "should configure #{client} idempotently" do
          apply_manifest_on(client, manifest, :catch_changes => true)
        end

        it "should collect #{client} iptables messages to host-specific iptables.log" do
          # Set up iptables to disallow icmp requests
          on(client, 'iptables --list-rules')
          on(client, 'iptables -N LOG_AND_DROP')
          on(client, 'iptables -A LOG_AND_DROP -j LOG --log-prefix "IPT:"')
          on(client, 'iptables -A LOG_AND_DROP -j DROP')
          on(client, 'iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j LOG_AND_DROP')
          on(client, 'ping -c 1 `facter ipaddress`', :accept_all_exit_codes => true)
          result = on(server, "grep -l 'IPT:' #{client_log_dir}/iptables.log")
          expect(result.stdout.strip).to eq("#{client_log_dir}/iptables.log")

          # clean up iptables rules to allow any future tests using the
          # SIMP iptables module to start with a clean slate
          on(client, 'iptables --delete LOG_AND_DROP -j LOG --log-prefix "IPT:"')
          on(client, 'iptables --delete LOG_AND_DROP -j DROP')
          on(client, 'iptables --delete INPUT -p icmp -m icmp --icmp-type 8 -j LOG_AND_DROP')
          on(client, 'iptables -X LOG_AND_DROP')
          on(client, 'iptables --list-rules')
        end
  
        it "should collect #{client} messages to host-specific files" do
          # Each entry in this array is [log_options, log_message, log_file]
          # When log_file is nil, this means the log is NOT forwarded.
          default_test_array = [
            ['-p local7.warning -t boot',   'CLIENT_FORWARDED_BOOT_LOG',         'boot.log'],
            ['-p mail.info -t id1',         'CLIENT_FORWARDED_ANY_MAIL_LOG',     nil], # if forwarded would be mail.log
            ['-p cron.warning -t cron',     'CLIENT_FORWARDED_CRON_ANY_LOG',     'cron.log'],
            ['-p local4.emerg -t id2',      'CLIENT_FORWARDED_ANY_EMERG_LOG',    'emergency.log'],
            ['-p local2.info -t sudosh',    'CLIENT_FORWARDED_SUDOSH_LOG',       'sudosh.log'],
            ['-p local6.err -t httpd',      'CLIENT_FORWARDED_HTTPD_ERR_LOG',    'httpd_error.log'],
            ['-p local6.warning -t httpd',  'CLIENT_FORWARDED_HTTPD_NO_ERR_LOG', 'httpd.log'],
            ['-t dhcpd',                    'CLIENT_FORWARDED_DHCPD_LOG',        nil], # if forwarded would be dhcpd.log
            ['-p local6.err -t puppet-agent',     'CLIENT_FORWARDED_PUPPET_AGENT_ERR_LOG',    'puppet_agent_error.log'],
            ['-p local6.warning -t puppet-agent', 'CLIENT_FORWARDED_PUPPET_AGENT_NO_ERR_LOG', 'puppet_agent.log'],
            ['-p local6.err -t puppetserver',     'CLIENT_FORWARDED_PUPPETSERVER_ERR_LOG',    'puppetserver_error.log'],
            ['-p local6.warning -t puppetserver', 'CLIENT_FORWARDED_PUPPETSERVER_NO_ERR_LOG', 'puppetserver.log'],
            ['-p local5.notice -t audispd', 'CLIENT_FORWARDED_AUDISPD_LOG',      'auditd.log'],
            ['-t slapd_audit',              'CLIENT_FORWARDED_SLAPD_AUDIT_LOG',  nil], # if forwarded would be slapd_audit.log
            ['-p news.crit -t news',        'CLIENT_FORWARDED_NEWS_CRIT_LOG',    nil], # if forwarded would be spool.log
            ['-p uucp.crit -t uucp',        'CLIENT_FORWARDED_UUCP_CRIT_LOG',    nil], # if forwarded would be spool.log
            ['-t sudo',                     'CLIENT_FORWARDED_SUDO_LOG',         'secure.log'],
            ['-t auditd',                   'CLIENT_FORWARDED_AUDITD_LOG',       'secure.log'],
            ['-t audit',                    'CLIENT_FORWARDED_AUDIT_LOG',        'secure.log'],
            ['-t yum',                      'CLIENT_FORWARDED_YUM_LOG',          'secure.log'],
            ['-t systemd',                  'CLIENT_FORWARDED_SYSTEMD_LOG',      'secure.log'],
            ['-t crond',                    'CLIENT_FORWARDED_CROND_LOG',        'secure.log'],
            ['-p authpriv.warning -t auth', 'CLIENT_FORWARDED_AUTHPRIV_ANY_LOG', 'secure.log'],
            ['-p local6.info -t id3',       'CLIENT_FORWARDED_LOCAL6_ANY_LOG',   'secure.log']
          ]

          # send the messages
          default_test_array.each do |options,message,logfile|
            on(client,"logger #{options} #{message}")
          end

          wait_for_log_message(server, File.join(client_log_dir, default_test_array[-1][2]),
            default_test_array[-1][1])

          # verify messages are forwarded and persisted, as appropriate
          default_test_array.each do |options,message,logfile|
            if logfile
              # Ensure message ended up in the intended log.
              result = on(server, "grep -Rl #{message} #{client_log_dir}")
              expect(result.stdout.strip).to eq("#{client_log_dir}/#{logfile}")
            else
              # Ensure message is not forwarded.
              on(server, "grep -Rl #{message} #{client_log_dir}", :acceptable_exit_codes => [1])
            end
          end
        end
      end
    end
  end
end
