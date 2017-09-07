require 'spec_helper'

file_content_7 = '/usr/bin/systemctl restart rsyslog > /dev/null 2>&1 || true'
file_content_6 = '/sbin/service rsyslog restart > /dev/null 2>&1 || true'

describe 'simp_rsyslog' do
  shared_examples_for 'a structured module' do
    it { is_expected.to compile.with_all_deps }
    it { is_expected.to contain_class('simp_rsyslog') }
  end

  on_supported_os.each do |os, facts|
    context "on #{os}" do
      let(:facts) do
        facts
      end

      let(:program_logs) do
        [ "($programname == 'sudo')",
          "($programname == 'sudosh')",
          "($programname == 'yum')",
          "($programname == 'audispd')",
          "($programname == 'auditd')",
          "($programname == 'audit')",
          "($programname == 'systemd')",
          "($programname == 'crond')",
          "($programname == 'snmpd')",
          "($programname == 'aide')"
        ]
      end

      let(:facility_logs) do
        [ "prifilt('cron.*')",
          "prifilt('authpriv.*')",
          "prifilt('local6.*')",
          "prifilt('local7.warn')",
          "prifilt('*.emerg')",
        ]
      end

      let(:msg_starts_logs) do
        [ "($msg startswith ' IPT:')",
          "($msg startswith 'IPT:')"
        ]
      end

      let(:default_security_relevant_logs) do
        (program_logs + facility_logs + msg_starts_logs).join(' or ')
      end

      let (:residual_security_logs) do
        [ "($programname == 'sudo')",
          "($programname == 'sudosh')",
          "($programname == 'audit')",
          "($programname == 'auditd')",
          "($programname == 'yum')",
          "($programname == 'systemd')",
          "($programname == 'crond')",
          "prifilt('local7.warn')",
          "prifilt('*.emerg')"
        ].join(' or ')
      end

      context 'simp_rsyslog class with default parameters' do
        let(:params) {{ }}
        it_behaves_like 'a structured module'
        it { is_expected.to contain_class('simp_rsyslog::local') }
        it { is_expected.to contain_rsyslog__rule__local('ZZ_01_simp_rsyslog_profile_local_drop_audispd_duplicates') }
        it {
          is_expected.to contain_rsyslog__rule__local('ZZ_02_simp_rsyslog_profile_local_security').with_rule(
            Regexp.new(Regexp.escape(residual_security_logs))
          )
        }
        it { is_expected.to contain_rsyslog__rule__local('ZZ_02_simp_rsyslog_profile_local_security').with_stop_processing(true) }
        it { is_expected.not_to contain_class('simp_rsyslog::server') }
        it { is_expected.not_to contain_class('simp_rsyslog::forward') }
      end

      context 'simp rsyslog class that enables forwarding' do
        context 'forwarding default logs' do
          let(:params) {{
            :forward_logs => true,
            :log_servers  => ['1.2.3.4']
          }}

          it_behaves_like 'a structured module'
          it { is_expected.to contain_class('simp_rsyslog::local') }
          it { is_expected.to contain_class('simp_rsyslog::forward') }
          it {
            is_expected.to contain_rsyslog__rule__remote('99_simp_rsyslog_profile_remote').with(
             {
              :rule                 => Regexp.new(Regexp.escape(default_security_relevant_logs)),
              :dest                 => ['1.2.3.4'],
              :failover_log_servers => [],
              :dest_type            => 'tcp',
              :stop_processing      => false
             }
            )
          }
          it { is_expected.not_to contain_class('simp_rsyslog::server') }
        end

        context 'forwarding all logs but disable local rsyslog configuration' do
          let(:params){{
            :forward_logs         => true,
            :log_servers          => ['1.2.3.4'],
            :failover_log_servers => ['3.4.5.6'],
            :collect_everything   => true,
            :log_local            => false
          }}

          it_behaves_like 'a structured module'
          it { is_expected.to contain_class('simp_rsyslog::forward') }
          it {
            is_expected.to contain_rsyslog__rule__remote('99_simp_rsyslog_profile_remote').with(
             {
              :rule                 => "prifilt('*.*')",
              :dest                 => ['1.2.3.4'],
              :failover_log_servers => ['3.4.5.6'],
              :dest_type            => 'tcp',
              :stop_processing      => false
             }
            )
          }
          it { is_expected.not_to contain_class('simp_rsyslog::local') }
          it { is_expected.not_to contain_class('simp_rsyslog::server') }
        end

        context 'with openldap log forwarding enabled' do
          let(:params) {{
            :forward_logs => true,
            :log_servers  => ['1.2.3.4'],
            :log_openldap => true
          }}
  
          it_behaves_like 'a structured module'
          it {
            logs = program_logs + [ "($programname == 'slapd')" ] +
              facility_logs + [ "prifilt('local4.*')" ] + msg_starts_logs
            expected_logs = logs.join(' or ')
            is_expected.to contain_rsyslog__rule__remote('99_simp_rsyslog_profile_remote').with_rule(
              Regexp.new(Regexp.escape(expected_logs))
            )
          }
        end
  
        context 'custom log forwarding' do
          let(:params) {{
            :forward_logs => true,
            :log_servers  => ['1.2.3.4'],
            :log_collection => {
              'facilities' => ['local2.warn']
             }
          }}
  
          it_behaves_like 'a structured module'
          it {
            logs = program_logs + facility_logs + [ "prifilt('local2.warn')" ] +
              msg_starts_logs
            expected_logs = logs.join(' or ')
            is_expected.to contain_rsyslog__rule__remote('99_simp_rsyslog_profile_remote').with_rule(
              Regexp.new(Regexp.escape(expected_logs))
            )
          }
        end

        context 'with remote log servers not specified' do
          let(:params) {{
            :forward_logs => true,
            :log_servers  => [],
          }}
          it { is_expected.not_to compile.with_all_deps }
        end
      end

      context 'simp_rsyslog class that is a log server' do
        context 'with default parameters' do
          let(:params) {{
            :is_server => true
          }}
          it_behaves_like 'a structured module'
          it { is_expected.to contain_class('simp_rsyslog::server') }
          it { is_expected.to contain_rsyslog__rule__local('10_00_default_boot') }
          it { is_expected.to contain_rsyslog__rule__local('10_00_default_mail') }
          it { is_expected.to contain_rsyslog__rule__local('10_00_default_cron') }
          it { is_expected.to contain_rsyslog__rule__local('10_00_default_emerg') }
          it { is_expected.to contain_rsyslog__rule__local('10_default_sudosh') }
          it { is_expected.to contain_rsyslog__rule__local('10_default_httpd_error') }
          it { is_expected.to contain_rsyslog__rule__local('11_default_httpd') }
          it { is_expected.to contain_rsyslog__rule__local('10_default_dhcpd') }
          it { is_expected.to contain_rsyslog__rule__local('10_default_snmpd') }
          it { is_expected.to contain_rsyslog__rule__local('10_default_puppet_agent_error') }
          it { is_expected.to contain_rsyslog__rule__local('11_default_puppet_agent') }
          it { is_expected.to contain_rsyslog__rule__local('10_default_puppetserver_error') }
          it { is_expected.to contain_rsyslog__rule__local('11_default_puppetserver') }
          it { is_expected.to contain_rsyslog__rule__local('10_default_audit') }
          it { is_expected.to contain_rsyslog__rule__local('10_default_aide') }
          it { is_expected.to contain_rsyslog__rule__local('10_default_slapd_audit') }
          it { is_expected.to contain_rsyslog__rule__local('10_default_iptables') }
          it { is_expected.to contain_rsyslog__rule__local('10_default_kern') }
          it { is_expected.to contain_rsyslog__rule__local('10_default_spool') }
          it { is_expected.to contain_rsyslog__rule__local('17_default_security_relevant_logs').with_rule(
              Regexp.new(Regexp.escape(default_security_relevant_logs))
          ) }
          it { is_expected.to contain_rsyslog__rule__local('19_default_message') }
          it { is_expected.to contain_rsyslog__rule__local('30_default_catchall') }
          it { is_expected.not_to contain_rsyslog__rule__local('30_default_drop') }
          it { is_expected.to contain_class('logrotate') }
          if ['RedHat','CentOS'].include?(facts[:operatingsystem])
            if facts[:operatingsystemmajrelease].to_s < '7'
              it { should create_file('/etc/logrotate.d/simp_rsyslog_server_profile').with_content(/#{file_content_6}/)}
            else
              it { should create_file('/etc/logrotate.d/simp_rsyslog_server_profile').with_content(/#{file_content_7}/)}
            end
          end
        end

        context 'simp_rsyslog class that is a log server with all features disabled' do
          # no reason to disable all, but this allows testing of individual disable
          # parameters
          let(:params) {{
            :is_server => true
          }}
          let(:hieradata) { 'rsyslog_server_features_disabled' }
          it_behaves_like 'a structured module'
          it { is_expected.to contain_class('simp_rsyslog::server') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_00_default_boot') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_00_default_mail') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_00_default_cron') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_00_default_emerg') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_default_sudosh') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_default_httpd_error') }
          it { is_expected.not_to contain_rsyslog__rule__local('11_default_httpd') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_default_dhcpd') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_default_snmpd') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_default_puppet_agent_error') }
          it { is_expected.not_to contain_rsyslog__rule__local('11_default_puppet_agent') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_default_puppetserver_error') }
          it { is_expected.not_to contain_rsyslog__rule__local('11_default_puppetserver') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_default_audit') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_default_aide') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_default_slapd_audit') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_default_iptables') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_default_kern') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_default_spool') }
          it { is_expected.not_to contain_rsyslog__rule__local('17_default_security_relevant_logs') }
          it { is_expected.not_to contain_rsyslog__rule__local('19_default_message') }
          it { is_expected.not_to contain_rsyslog__rule__local('30_default_catchall') }
          it { is_expected.not_to contain_rsyslog__rule__local('30_default_drop') }
          it { is_expected.not_to contain_logrotate__rule('simp_rsyslog_server_profile') }
        end

        context 'simp_rsyslog class that is a log server with custom rules' do
          let(:params) {{
            :is_server => true
          }}
          let(:hieradata) { 'rsyslog_server_custom_rules' }
          it_behaves_like 'a structured module'
          it { is_expected.to contain_class('simp_rsyslog::server') }
          it { is_expected.to contain_rsyslog__rule__drop('0_default').with_rule('prifilt(\'*.*\')') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_00_default_boot') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_00_default_mail') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_00_default_cron') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_00_default_emerg') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_default_sudosh') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_default_httpd_error') }
          it { is_expected.not_to contain_rsyslog__rule__local('11_default_httpd') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_default_dhcpd') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_default_snmpd') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_default_puppet_agent_error') }
          it { is_expected.not_to contain_rsyslog__rule__local('11_default_puppet_agent') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_default_puppetserver_error') }
          it { is_expected.not_to contain_rsyslog__rule__local('11_default_puppetserver') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_default_audit') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_default_aide') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_default_slapd_audit') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_default_iptables') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_default_kern') }
          it { is_expected.not_to contain_rsyslog__rule__local('10_default_spool') }
          it { is_expected.not_to contain_rsyslog__rule__local('17_default_security_relevant_logs') }
          it { is_expected.not_to contain_rsyslog__rule__local('19_default_message') }
          it { is_expected.not_to contain_rsyslog__rule__local('30_default_catchall') }
          it { is_expected.not_to contain_rsyslog__rule__local('30_default_drop') }
          it { is_expected.not_to contain_logrotate__rule('simp_rsyslog_server_profile') }
        end
      end
    end
  end
end
