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
include 'iptables'

iptables::listen::tcp_stateful { 'allow_sshd':
  order => 8,
  trusted_nets => ['ALL'],
  dports => 22,
}

iptables::rule { 'log_pings':
  order => 0,
  content => '-A LOCAL-INPUT -p icmp -m icmp --icmp-type 8 -j LOG --log-prefix "IPT:"',
  apply_to => 'ipv4',
}
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
simp_options::firewall: true
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
rsyslog::trusted_nets:
  - 'ALL'
simp_options::firewall: true
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

        it "should collect #{client} iptables messages to host-specific, server iptables.log, as well as client iptables.log" do
          # Set up iptables to log icmp requests
          on(client, 'ping -c 3 `facter ipaddress`', :accept_all_exit_codes => true)
          result = on(server, "grep -l 'IPT:' #{client_log_dir}/iptables.log")
          expect(result.stdout.strip).to eq("#{client_log_dir}/iptables.log")
          result = on(client, "grep -l 'IPT:' /var/log/iptables.log")
          expect(result.stdout.strip).to eq('/var/log/iptables.log')
        end
  
        it "should collect #{client} messages to host-specific, server logs, as well as client logs" do
          # Each entry in this array is [log_options, log_message, server_logfile, client_logfile]
          # server_logfile is the relative log file in the client-specific directory;
          #   when nil, this means the log is NOT forwarded.
          # client_logfile is the relative, local log file on the client;
          #   when nil, this means the log is dropped
          default_test_array = [
            ['-p local7.warning -t boot',   'CLIENT_FORWARDED_BOOT_LOG',         'boot.log',        'secure'],
            ['-p mail.info -t id1',         'CLIENT_FORWARDED_ANY_MAIL_LOG',     nil,               'maillog'],
            ['-p cron.warning -t cron',     'CLIENT_FORWARDED_CRON_ANY_LOG',     'cron.log',        'cron'],
            ['-p local4.emerg -t id2',      'CLIENT_FORWARDED_ANY_EMERG_LOG',    'emergency.log',   'secure'],
            ['-p local2.info -t sudosh',    'CLIENT_FORWARDED_SUDOSH_LOG',       'sudosh.log',      'messages'], # local='sudosh.log' when sudosh module used
            ['-p local2.info -t tlog',    'CLIENT_FORWARDED_TLOG_LOG',           'tlog.log',        'messages'], # local='tlog.log' when tlog module used
            ['-p local6.err -t httpd',      'CLIENT_FORWARDED_HTTPD_ERR_LOG',    'httpd_error.log', 'secure'], # local='httpd/error_log' when simp_apache is installed
            ['-p local6.warning -t httpd',  'CLIENT_FORWARDED_HTTPD_NO_ERR_LOG', 'httpd.log',       'secure'], # local='httpd/access_log' when simp_apache is installed
            ['-t dhcpd',                    'CLIENT_FORWARDED_DHCPD_LOG',        nil,               'messages'], # local='dhcpd' when dhcp is installed
            ['-p local6.info -t snmpd',     'CLIENT_FORWARDED_SNMPD_LOG',        'snmpd.log',       'secure'], # local='snmpd.log' when snmpd is installed
            ['-p local6.notice -t aide',    'CLIENT_FORWARDED_AIDE_LOG',         'aide.log',        'secure'], # local='aide/aide.log' when aide is installed
            ['-p local6.err -t puppet-agent',     'CLIENT_FORWARDED_PUPPET_AGENT_ERR_LOG',     'puppet_agent_error.log', 'puppet-agent-err.log'],
            ['-p local6.warning -t puppet-agent', 'CLIENT_FORWARDED_PUPPET_AGENT_NO_ERR_LOG',  'puppet_agent.log',       'puppet-agent.log'],
            ['-p local6.err -t puppetserver',     'CLIENT_FORWARDED_PUPPETSERVER_ERR_LOG',     'puppetserver_error.log', 'puppetserver-err.log'],
            ['-p local6.warning -t puppetserver', 'CLIENT_FORWARDED_PUPPETSERVER_NO_ERR_LOG',  'puppetserver.log',       'puppetserver.log'],
            ['-p local5.notice -t audispd', 'CLIENT_FORWARDED_AUDISPD_LOG',      'auditd.log',  nil],  # locally defeated as already in /var/log/audit when real audispd message
            ['-t slapd_audit',              'CLIENT_FORWARDED_SLAPD_AUDIT_LOG',  nil,          'slapd_audit.log'],
            ['-p news.crit -t news',        'CLIENT_FORWARDED_NEWS_CRIT_LOG',    nil,          'spooler'], #syslog module FIXME also appears in messages
            ['-p uucp.crit -t uucp',        'CLIENT_FORWARDED_UUCP_CRIT_LOG',    nil,          'spooler'], #syslog module FIXME also appears in messages, locally
            ['-t sudo',                     'CLIENT_FORWARDED_SUDO_LOG',         'secure.log', 'secure'],
            ['-t auditd',                   'CLIENT_FORWARDED_AUDITD_LOG',       'secure.log', 'secure'],
            ['-t audit',                    'CLIENT_FORWARDED_AUDIT_LOG',        'secure.log', 'secure'],
            ['-t yum',                      'CLIENT_FORWARDED_YUM_LOG',          'secure.log', 'secure'],
            ['-t systemd',                  'CLIENT_FORWARDED_SYSTEMD_LOG',      'secure.log', 'secure'],
            ['-t crond',                    'CLIENT_FORWARDED_CROND_LOG',        'secure.log', 'secure'],
            ['-p authpriv.warning -t auth', 'CLIENT_FORWARDED_AUTHPRIV_ANY_LOG', 'secure.log', 'secure'],
            ['-p local6.info -t id3',       'CLIENT_FORWARDED_LOCAL6_ANY_LOG',   'secure.log', 'secure']
          ]

          # send the messages
          default_test_array.each do |options,message,logfile|
            on(client,"logger #{options} #{message}")
          end

          wait_for_log_message(server, File.join(client_log_dir, default_test_array[-1][2]),
            default_test_array[-1][1])

          # verify messages are forwarded and persisted, as appropriate
          default_test_array.each do |options,message,server_logfile,client_logfile|
            if server_logfile
              # Ensure message ended up in the intended log.
              result = on(server, "grep -Rl '#{message}' #{client_log_dir}")
              expect(result.stdout.strip).to eq("#{client_log_dir}/#{server_logfile}")
            else
              # Ensure message is not forwarded.
              on(server, "grep -Rl '#{message}' #{client_log_dir}", :acceptable_exit_codes => [1])
            end
            if client_logfile
              # Ensure messages are still logged on the client
              result = on(client, "grep -l '#{message}' /var/log/#{client_logfile}")
              if (message == 'CLIENT_FORWARDED_NEWS_CRIT_LOG' or 
                  message == 'CLIENT_FORWARDED_UUCP_CRIT_LOG')
                # logged to /var/log/spooler AND /var/log/messages because of syslog module bug
                expect(result.stdout.strip).to match(/\/var\/log\/#{client_logfile}/)
              else
                expect(result.stdout.strip).to eq("/var/log/#{client_logfile}")
              end
            else
              # Ensure dropped message (e.g., duplicate auditd messages)
              # are not logged on the client
              on(client, "grep -Rl '#{message}' /var/log", :acceptable_exit_codes => [1])
            end
          end
        end
      end
    end
  end
end
