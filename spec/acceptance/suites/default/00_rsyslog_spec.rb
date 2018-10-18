require 'spec_helper_acceptance'

test_name 'simp_rsyslog profile'

describe 'simp_rsyslog' do
  let(:manifest) {
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
  let(:hieradata) {
    <<-EOS
---
simp_options::firewall: true
    EOS
  }

  hosts_with_role(hosts, 'rsyslog_client').each do |host|
    context "local-only logging on #{host.name}" do
      it 'should configure the system without errors' do
        set_hieradata_on(host, hieradata)
        apply_manifest_on(host, manifest, :catch_failures => true)
        #rsyslog setup requires 2 passes first install rsyslog
        #then configure rsyslog
        apply_manifest_on(host, manifest, :catch_failures => true)
      end

      it 'should configure the system idempotently' do
        apply_manifest_on(host, manifest, :catch_changes => true)
      end

      it 'should drop duplicate audispd log messages' do
        # log message identified by program name
        on(host, 'logger -p local5.notice -t audispd LOCAL_ONLY_AUDISPD_DROP')
        sleep(5)

        on(host, 'grep -r LOCAL_ONLY_AUDISPD_DROP /var/log', :acceptable_exit_codes => [1])
      end

      it 'should collect iptables log messages in /var/log/iptables.log' do
        # Set up iptables to log icmp requests
        on(host, 'ping -c 3 `facter ipaddress`', :accept_all_exit_codes => true)
        check = on(host, "grep -l 'IPT:' /var/log/iptables.log").stdout.strip
        expect(check).to eq('/var/log/iptables.log')
      end

      it 'should collect other security relevant log messages in /var/log/secure' do
        # some of the rules come from simp_rsyslog and some from rsyslog
        # log messages identified by program name
        on(host, 'logger -t auditd LOCAL_ONLY_AUDITD_LOG')
        on(host, 'logger -t audit LOCAL_ONLY_AUDIT_LOG')
        on(host, 'logger -t sudo LOCAL_ONLY_SUDO_LOG')
        on(host, 'logger -t yum LOCAL_ONLY_YUM_LOG')
        on(host, 'logger -t systemd LOCAL_ONLY_SYSTEMD_LOG')

        # log messages identified by facility and/or priority
        on(host, 'logger -t crond LOCAL_ONLY_CROND_LOG')
        on(host, 'logger -p authpriv.warning -t auth LOCAL_ONLY_AUTHPRIV_ANY_LOG')
        on(host, 'logger -p local5.notice -t id2 LOCAL_ONLY_LOCAL5_ANY_LOG')
        on(host, 'logger -p local6.info -t httpd LOCAL_ONLY_LOCAL6_ANY_LOG')
        on(host, 'logger -p local7.warning -t id3 LOCAL_ONLY_LOCAL7_WARN_LOG')
        on(host, 'logger -p local4.emerg -t id4 LOCAL_ONLY_ANY_EMERG_LOG')

        wait_for_log_message(host, '/var/log/secure', 'LOCAL_ONLY_ANY_EMERG_LOG')

        [ 'LOCAL_ONLY_AUDITD_LOG',
          'LOCAL_ONLY_AUDIT_LOG',
          'LOCAL_ONLY_SUDO_LOG',
          'LOCAL_ONLY_YUM_LOG',
          'LOCAL_ONLY_SYSTEMD_LOG',
          'LOCAL_ONLY_CROND_LOG',
          'LOCAL_ONLY_AUTHPRIV_ANY_LOG',
          'LOCAL_ONLY_LOCAL5_ANY_LOG',
          'LOCAL_ONLY_LOCAL6_ANY_LOG',
          'LOCAL_ONLY_LOCAL7_WARN_LOG',
          'LOCAL_ONLY_ANY_EMERG_LOG',
        ].each do |message|
            check = on(host, "grep -l '#{message}' /var/log/secure").stdout.strip
            expect(check).to eq('/var/log/secure')
        end
      end

      it 'should collect puppet-agent log messages in /var/log/puppet-agent*.log' do
        on(host, 'logger -p local6.err -t puppet-agent LOCAL_ONLY_PUPPET_AGENT_ERR')
        on(host, 'logger -p local6.notice -t puppet-agent LOCAL_ONLY_PUPPET_AGENT_NOTICE')
        wait_for_log_message(host, '/var/log/puppet-agent.log', 'LOCAL_ONLY_PUPPET_AGENT_NOTICE')

        check = on(host, 'grep -l LOCAL_ONLY_PUPPET_AGENT_ERR /var/log/puppet-agent-err.log').stdout.strip
        expect(check).to eq('/var/log/puppet-agent-err.log')
        check = on(host, 'grep -l LOCAL_ONLY_PUPPET_AGENT_ERR /var/log/puppet-agent.log').stdout.strip
        expect(check).to eq('/var/log/puppet-agent.log')
        check = on(host, 'grep -l LOCAL_ONLY_PUPPET_AGENT_NOTICE /var/log/puppet-agent.log').stdout.strip
        expect(check).to eq('/var/log/puppet-agent.log')
      end

      it 'should collect puppetserver log messages in /var/log/puppetserver*.log' do
        on(host, 'logger -p local6.err -t puppetserver LOCAL_ONLY_PUPPET_SERVER_ERR')
        on(host, 'logger -p local6.notice -t puppetserver LOCAL_ONLY_PUPPET_SERVER_NOTICE')
        wait_for_log_message(host, '/var/log/puppetserver.log', 'LOCAL_ONLY_PUPPET_SERVER_NOTICE')

        check = on(host, 'grep -l LOCAL_ONLY_PUPPET_SERVER_ERR /var/log/puppetserver-err.log').stdout.strip
        expect(check).to eq('/var/log/puppetserver-err.log')
        check = on(host, 'grep -l LOCAL_ONLY_PUPPET_SERVER_ERR /var/log/puppetserver.log').stdout.strip
        expect(check).to eq('/var/log/puppetserver.log')
        check = on(host, 'grep -l LOCAL_ONLY_PUPPET_SERVER_NOTICE /var/log/puppetserver.log').stdout.strip
        expect(check).to eq('/var/log/puppetserver.log')
      end

      it 'should collect slapd log messages in /var/log/slapd_audit.log' do
        on(host, 'logger -t slapd_audit LOCAL_ONLY_SLAPD_AUDIT')
        wait_for_log_message(host, '/var/log/slapd_audit.log', 'LOCAL_ONLY_SLAPD_AUDIT')
      end

      it 'should collect cron log messages in /var/log/cron' do
        on(host, 'logger -p cron.warning -t cron LOCAL_ONLY_CRON_ANY_LOG')
        wait_for_log_message(host, '/var/log/cron', 'LOCAL_ONLY_CRON_ANY_LOG')
      end
    end
  end
end
