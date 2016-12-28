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

  let(:servers) { hosts_with_role( hosts, 'rsysserver' ) }

  let(:server_manifest) {
    <<-EOS
      include 'simp_rsyslog'
    EOS
  }
  let(:server_hieradata) {
    <<-EOS
---
rsyslog::pki: false
simp_rsyslog::is_server: true
    EOS
}

let(:server_disable01_hieradata) {
    <<-EOS
#{server_hieradata}
simp_rsyslog::server::process_sudosh_rules: false
simp_rsyslog::server::process_httpd_rules: false
simp_rsyslog::server::process_dcpd_rules: false
simp_rsyslog::server::process_puppet_agent_rules: false
simp_rsyslog::server::process_puppetserver_rules: false
simp_rsyslog::server::process_auditd_rules: false
simp_rsyslog::server::process_slapd_rules: false
simp_rsyslog::server::process_kern_rules: false
simp_rsyslog::server::process_iptables_rules: false
simp_rsyslog::server::process_message_rules: false
simp_rsyslog::server::process_mail_rules: false
simp_rsyslog::server::process_cron_rules: false
simp_rsyslog::server::process_emerg_rules: false
simp_rsyslog::server::process_spool_rules: false
simp_rsyslog::server::process_boot_rules: false
    EOS
  }

  let(:server_disable017_hieradata) {
    <<-EOS
#{server_hieradata}
simp_rsyslog::server::process_sudosh_rules: false
simp_rsyslog::server::process_httpd_rules: false
simp_rsyslog::server::process_dcpd_rules: false
simp_rsyslog::server::process_puppet_agent_rules: false
simp_rsyslog::server::process_puppetserver_rules: false
simp_rsyslog::server::process_auditd_rules: false
simp_rsyslog::server::process_slapd_rules: false
simp_rsyslog::server::process_kern_rules: false
simp_rsyslog::server::process_iptables_rules: false
simp_rsyslog::server::process_message_rules: true
simp_rsyslog::server::process_mail_rules: false
simp_rsyslog::server::process_cron_rules: false
simp_rsyslog::server::process_emerg_rules: false
simp_rsyslog::server::process_spool_rules: false
simp_rsyslog::server::process_boot_rules: false
simp_rsyslog::server::process_security_relevant_logs: false
    EOS
  }

  # Test simp_rsyslog::server
  #
  #
  context 'with is_server = true' do
    it 'should configure the server without erros' do
      servers.each do |server|
        set_hieradata_on(server, server_hieradata)
        apply_manifest_on(server, server_manifest, :catch_failures => true)
      end
    end
    it 'should configure the servers idempotently' do
      servers.each do |server|
        apply_manifest_on(server, server_manifest, :catch_changes => true)
      end
    end

    # Log Server Test1: Ensure syslog messages are processed by their
    # intended rule(s), and that there are no re-processed messages (duplicates).
    #
    # Log_servers uses a 3 tier log-local rule hierarchy:
    #   0/1 - facility specific logs
    #   7   - secure.log (security relevant logs)
    #   9   - messages.log
    #
    # Each takes precedence over the next.  For instance, if a
    # 7 rule encompasses a 0/1 rule, the 0/1 rule should process the log message
    # first, then stop processing such that the 7 or 9 rule will not process it.
    #
    # This testing scheme iterates over every 0/1 rule in server.pp, and
    # ensures it is not re-processed by 7/9 rules.  7 rules encompassed by 9 rules
    # are tested as well.
    #
    #
    it 'testing default server rules' do
      servers.each do |server|
        # 0/1 rules
        # 
        on server, "logger -t sudosh LOGGERSUDOSH"
        on server, "logger -p local0.warn -t httpd LOGGERHTTPDNOERR"
        on server, "logger -p local0.err -t httpd LOGGERHTTPDERR"
        on server, "logger -t dhcpd LOGGERDHCP"
        on server, "logger -p local0.err -t puppet LOGGERPUPPETAGENTERR"
        on server, "logger -p local0.warn -t puppet LOGGERPUPPETAGENTNOERR"
        on server, "logger -p local0.err -t puppetserver LOGGERPUPPETMASTERERR"
        on server, "logger -p local0.warn -t puppetserver LOGGERPUPPETMASTERNOERR"
        # NOTE: on server, "logger -t audispd LOGGERAUDISPD * does not work!"
        on server, "logger -t audispd LOGGERTAGAUDITLOG"
        on server, "logger -t slapd_audit LOGGERSLAPDAUDIT"
        # NOTE: on server, "IPT does not work!" see logger man page for
        # potential kern issues
        on server, "logger -p mail.warn -t mail LOGGERMAIL"
        on server, "logger -p cron.warn -t cron LOGGERCRON"
        # TODO: test console output for emerge
        on server, "logger -p cron.emerg -t cron LOGGEREMERG"
        on server, "logger -p news.crit -t news LOGGERNEWS"
        on server, "logger -p uucp.warn -t uucp LOGGERUUCP"
        on server, "logger -p local7.warn -t boot LOGGERBOOT"
        # 7 rules
        #
        on server, "logger -t yum LOGGERYUM"
        on server, "logger -p authpriv.warn -t auth LOGGERAUTHPRIV"
        on server, "logger -p local5.warn -t local5 LOGGERLOCAL5"
        on server, "logger -p local6.warn -t local6 LOGGERLOCAL6"
        # 9 rules
        #
        on server, "logger -p local0.info -t info LOGGERINFO"

        # This array maps each tag's message, above, to its template file (log file).
        test_array = [
          ["LOGGERSUDOSH", "sudosh.log"],
          ["LOGGERHTTPDNOERR", "httpd.log"],
          ["LOGGERHTTPDERR", "httpd_error.log"],
          ["LOGGERDHCP", "dhcpd.log"],
          ["LOGGERPUPPETAGENTERR", "puppet_agent_error.log"],
          ["LOGGERPUPPETAGENTNOERR", "puppet_agent.log"],
          ["LOGGERPUPPETMASTERERR", "puppetserver_error.log"],
          ["LOGGERPUPPETMASTERNOERR", "puppetserver.log"],
          ["LOGGERTAGAUDITLOG", "auditd.log"],
          ["LOGGERLOCAL5", "auditd.log"],
          ["LOGGERSLAPDAUDIT", "slapd_audit.log"],
          ["LOGGERMAIL", "mail.log"],
          ["LOGGERCRON", "cron.log"],
          ["LOGGEREMERG", "cron.log"],
          ["LOGGERNEWS", "spool.log"],
          ["LOGGERUUCP", "spool.log"],
          ["LOGGERBOOT", "boot.log"],
          ["LOGGERYUM", "secure.log"],
          ["LOGGERAUTHPRIV", "secure.log"],
          ["LOGGERLOCAL6", "secure.log"],
          ["LOGGERINFO", "messages.log"]]

        result_dir = "/var/log/hosts/#{fact_on(server,'fqdn')}"

        # Ensure each message ended up in the intended log.
        test_array.each do |message|
          result = on server, "grep -Rl #{message[0]} #{result_dir}"
          expect(result.stdout.strip).to eq("#{result_dir}/#{message[1]}")
        end
      end
    end

    # Log Server Test2: Disable all 0/1 stop rules and test 7/9 rules.
    #
    #
    it 'should disable 0/1 rules' do
      servers.each do |server|
        set_hieradata_on(server, server_disable01_hieradata)
        apply_manifest_on(server, server_manifest, :catch_failures => true)
      end
    end
    it 'testing server with 0/1 stop rules disabled' do
      servers.each do |server|
        on server, "logger -t sudosh LOGGERSUDOSHSECURE"
        on server, "logger -t yum LOGGERYUMSECURE"
        on server, "logger -p cron.warn -t cron LOGGERCRONWARNSECURE"
        on server, "logger -p authpriv.warn -t auth LOGGERAUTHPRIVSECURE"
        on server, "logger -p local5.warn -t local5 LOGGERLOCAL5SECURE"
        on server, "logger -p local6.warn -t local6 LOGGERLOCAL6SECURE"
        on server, "logger -p local7.warn -t boot BOOTSECURE"
        on server, "logger -p cron.emerg -t cron LOGGEREMERGSECURE"
        # NOTE: on server, "IPT does not work!" see logger man page for
        # potential kern issues

        test_array = ["LOGGERSUDOSHSECURE","LOGGERYUMSECURE",
                      "LOGGERCRONWARNSECURE", "LOGGERAUTHPRIVSECURE",
                      "LOGGERLOCAL6SECURE",
                      "BOOTSECURE", "LOGGEREMERGSECURE"]
        result_dir = "/var/log/hosts/#{fact_on(server,'fqdn')}"

        test_array.each do |message|
          result = on server, "grep -Rl #{message} #{result_dir}"
          expect(result.stdout.strip).to eq("#{result_dir}/secure.log")
        end
      end
    end

    # Log Server Test3: Disable all 0/1/7 stop rules and test 9 rules.
    #
    #
    it 'should disable 0/1/7 rules' do
      servers.each do |server|
        set_hieradata_on(server, server_disable017_hieradata)
        apply_manifest_on(server, server_manifest, :catch_failures => true)
      end
    end
    it 'testing server with 0/1/7 stop rules disabled' do
      servers.each do |server|
        on server, "logger -p local0.info -t local0 LOGGERLOCAL0MESSAGES"
        on server, "logger -p mail.warn -t mail LOGGERMAILNONEMESSAGES"
        on server, "logger -p authpriv.warn -t authpriv LOGGERAUTHPRIVNONEMESSAGES"
        on server, "logger -p cron.warn -t cron LOGGERCRONNONEMESSAGES"
        on server, "logger -p local6.warn -t local6 LOGGERLOCAL6NONEMESSAGES"
        on server, "logger -p local5.warn -t local5 LOGGERLOCAL5NONEMESSAGES"

        test_array = ["LOGGERMAILNONEMESSAGES", "LOGGERAUTHPRIVNONEMESSAGES",
                      "LOGGERCRONNONEMESSAGES", "LOGGERLOCAL6NONEMESSAGES",
                      "LOGGERLOCAL5NONEMESSAGES"]
        result_dir = "/var/log/hosts/#{fact_on(server,'fqdn')}"

        # *.info should be logged
        result = on server, "grep -Rl LOGGERLOCAL0MESSAGES #{result_dir}"
        expect(result.stdout.strip).to eq("#{result_dir}/messages.log")

        # Catchall should grab the rest
        test_array.each do |message|
          result = on server, "grep -Rl #{message} #{result_dir}"
          expect(result.stdout.strip).to eq("#{result_dir}/catchall.log")
        end
      end
    end
  end
end
