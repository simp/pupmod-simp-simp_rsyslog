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

  let(:server_manifest) {
    <<-EOS
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
  let(:server_hieradata) {
    <<-EOS
---
simp_rsyslog::is_server: true
simp_rsyslog::forward_logs: false
rsyslog::tcp_server: true
rsyslog::tls_tcp_server: false
rsyslog::pki: false
simp_options::firewall: true
    EOS
}

  hosts_with_role( hosts, 'rsyslog_server' ).each do |server|
    context "#{server} logging to the co-resident syslog server" do
      let(:log_dir) { "/var/log/hosts/#{fact_on(server,'fqdn')}" }

      it 'should configure the server without errors' do
        set_hieradata_on(server, server_hieradata)
        apply_manifest_on(server, server_manifest, :catch_failures => true)
        # Rsyslog needs to run twice to install then configure rsyslog
        apply_manifest_on(server, server_manifest, :catch_failures => true)
      end

      it 'should configure the servers idempotently' do
        apply_manifest_on(server, server_manifest, :catch_changes => true)
      end

      it 'should collect iptables messages to host-specific iptables.log' do
        # Set up iptables to log icmp requests
        on(server, 'ping -c 3 `facter ipaddress`', :accept_all_exit_codes => true)
        result = on(server, "grep -l 'IPT:' #{log_dir}/iptables.log")
        expect(result.stdout.strip).to eq("#{log_dir}/iptables.log")
      end

      it 'should collect messages to host-specific files' do
        # Each entry in this array is [log_options, log_message, log_file]
        default_test_array = [
          ['-p local7.warning -t boot',   'LOCAL_SERVER_BOOT_LOG',         'boot.log'],
          ['-p mail.info -t id1',         'LOCAL_SERVER_ANY_MAIL_LOG',     'mail.log'],
          ['-p cron.warning -t cron',     'LOCAL_SERVER_CRON_ANY_LOG',     'cron.log'],
          ['-p local4.emerg -t id2',      'LOCAL_SERVER_ANY_EMERG_LOG',    'emergency.log'],
          ['-p local2.info -t sudosh',    'LOCAL_SERVER_SUDOSH_LOG',       'sudosh.log'],
          ['-p local6.err -t httpd',      'LOCAL_SERVER_HTTPD_ERR_LOG',    'httpd_error.log'],
          ['-p local6.warn -t httpd',     'LOCAL_SERVER_HTTPD_NO_ERR_LOG', 'httpd.log'],
          ['-t dhcpd',                    'LOCAL_SERVER_DHCPD_LOG',        'dhcpd.log'],
          ['-t snmpd',                    'LOCAL_SERVER_SNMPD_LOG',        'snmpd.log'],
          ['-t aide',                     'LOCAL_SERVER_AIDE_LOG',         'aide.log'],
          ['-p local6.err -t puppet-agent',     'LOCAL_SERVER_PUPPET_AGENT_ERR_LOG',    'puppet_agent_error.log'],
          ['-p local6.warning -t puppet-agent', 'LOCAL_SERVER_PUPPET_AGENT_NO_ERR_LOG', 'puppet_agent.log'],
          ['-p local6.err -t puppetserver',     'LOCAL_SERVER_PUPPETSERVER_ERR_LOG',    'puppetserver_error.log'],
          ['-p local6.warning -t puppetserver', 'LOCAL_SERVER_PUPPETSERVER_NO_ERR_LOG', 'puppetserver.log'],
          ['-p local5.notice -t audispd', 'LOCAL_SERVER_AUDISPD_LOG',      'auditd.log'],
          ['-t slapd_audit',              'LOCAL_SERVER_SLAPD_AUDIT_LOG',  'slapd_audit.log'],
          ['-p news.crit -t news',        'LOCAL_SERVER_NEWS_CRIT_LOG',    'spool.log'],
          ['-p uucp.crit -t uucp',        'LOCAL_SERVER_UUCP_CRIT_LOG',    'spool.log'],
          ['-t auditd',                   'LOCAL_SERVER_AUDITD_LOG',       'secure.log'],
          ['-t audit',                    'LOCAL_SERVER_AUDIT_LOG',        'secure.log'],
          ['-t sudo',                     'LOCAL_SERVER_SUDO_LOG',         'secure.log'],
          ['-t yum',                      'LOCAL_SERVER_YUM_LOG',          'secure.log'],
          ['-t systemd',                  'LOCAL_SERVER_SYSTEMD_LOG',      'secure.log'],
          ['-t crond',                    'LOCAL_SERVER_CROND_LOG',        'secure.log'],
          ['-p authpriv.warning -t auth', 'LOCAL_SERVER_AUTHPRIV_ANY_LOG', 'secure.log'],
          ['-p local6.info -t id3',       'LOCAL_SERVER_LOCAL6_ANY_LOG',   'secure.log']
        ]

        # send the messages
        default_test_array.each do |options,message,logfile|
          on(server,"logger #{options} #{message}")
        end

        wait_for_log_message(server, File.join(log_dir, default_test_array[-1][2]),
          default_test_array[-1][1])

        # Ensure each message ended up in the intended log.
        default_test_array.each do |options,message,logfile|
          result = on(server, "grep -Rl #{message} #{log_dir}")
          expect(result.stdout.strip).to eq("#{log_dir}/#{logfile}")
        end
      end

      pending 'it should catch any unexpected messages'
      pending 'it should drop other messages'
    end
  end
end
