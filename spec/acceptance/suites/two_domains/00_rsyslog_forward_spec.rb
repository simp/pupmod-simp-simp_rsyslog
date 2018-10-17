require 'spec_helper_acceptance'

test_name 'simp_rsyslog profile'

describe 'simp_rsyslog' do

  let(:manifest) { <<-EOS
include 'simp_rsyslog'
EOS
  }
  rsyslog_server1 = hosts_with_role(hosts,'rsyslog_server1').first
  rsyslog_server2 = hosts_with_role(hosts,'rsyslog_server2').first
  let(:server1_fqdn){fact_on(rsyslog_server1, 'fqdn')}
  let(:server2_fqdn){fact_on(rsyslog_server2, 'fqdn')}
  let(:server_hieradata) {{
    'simp_options::syslog::log_servers' => [ "#{server1_fqdn}", "#{server2_fqdn}"],
    'rsyslog::app_pki_external_source'  => '/etc/pki/simp-testing/pki',
    'rsyslog::pki'                      => true,
    'simp_rsyslog::is_server'           => true,
    'simp_rsyslog::forward_logs'        => false,
    'rsyslog::tcp_server'               => true,
    'rsyslog::tls_tcp_server'           => true,
    # Need to let log servers accept from different domains.  The default
    # is just the domain of the log server.
    'rsyslog::config::tls_input_tcp_server_stream_driver_permitted_peers' => ['*.wayout.org' ,'*.my.domain']
  }}
  # Set up the servers first so they can both receive from the clients
  hosts_with_role(hosts, 'rsyslog_server').each do |server|

    it "should configure server #{server} without errors" do
      set_hieradata_on(server, server_hieradata)
      apply_manifest_on(server, manifest, :catch_failures => true)
      #Need to run twice, once to install and set fact and then configure
      apply_manifest_on(server, manifest, :catch_failures => true)
    end

    it "should configure #{server} idempotently" do
      apply_manifest_on(server, manifest, :catch_changes => true)
    end
  end

  hosts_with_role(hosts, 'rsyslog_server').each do |server|
    hosts_with_role(hosts, 'rsyslog_client').each do |client|
      context "#{client} logging to the remote syslog server #{server} with default forwarding" do
        let(:client_fqdn){ fact_on( client, 'fqdn' ) }
        let(:client_hieradata) {{
          'simp_options::syslog::log_servers' => ["#{server1_fqdn}","#{server2_fqdn}"],
          'rsyslog::app_pki_external_source'  => '/etc/pki/simp-testing/pki',
          'rsyslog::pki'                      => true,
          'rsyslog::enable_tls_logging'       => true,
          'simp_rsyslog::forward_logs'        => true
        }}

        let(:client_log_dir) { "/var/log/hosts/#{client_fqdn}" }

        it "should configure client #{client} without errors" do
          set_hieradata_on(client, client_hieradata)
          apply_manifest_on(client, manifest, :catch_failures => true)
          #Need to run twice, once to install and set fact and then configure
          apply_manifest_on(client, manifest, :catch_failures => true)
        end

        it "should configure #{client} idempotently" do
          apply_manifest_on(client, manifest, :catch_changes => true)
        end


        it "should collect #{client} messages to host-specific, server logs, as well as client logs" do

          # Each entry in this array is [log_options, log_message, server_logfile]
          # server_logfile is the relative log file in the client-specific directory
          default_test_array = [
            ['-p local4.emerg -t id2',            'FORWARDED_ANY_EMERG_LOG',           'emergency.log'],
            ['-p local6.err -t puppet-agent',     'FORWARDED_PUPPET_AGENT_ERR_LOG',    'puppet_agent_error.log'],
            ['-p local6.warning -t puppet-agent', 'FORWARDED_PUPPET_AGENT_NO_ERR_LOG', 'puppet_agent.log'],
            ['-p local6.err -t puppetserver',     'FORWARDED_PUPPETSERVER_ERR_LOG',    'puppetserver_error.log'],
            ['-p local6.warning -t puppetserver', 'FORWARDED_PUPPETSERVER_NO_ERR_LOG', 'puppetserver.log']
          ]

          # send the messages
          default_test_array.each do |options,message,server_logfile|
            on(client,"logger #{options} #{message}")
          end

          wait_for_log_message(
            server,
            File.join(client_log_dir,
            default_test_array[-1][2]),
            default_test_array[-1][1]
          )

          # verify messages are forwarded and persisted
          default_test_array.each do |options,message,server_logfile|
            # Ensure message ended up in the intended log.
            result = on(server, "grep -Rl '#{message}' #{client_log_dir}")
            expect(result.stdout.strip).to eq("#{client_log_dir}/#{server_logfile}")
          end
        end
      end
    end
  end
end
