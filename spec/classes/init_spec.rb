require 'spec_helper'

describe 'simp_rsyslog' do
  shared_examples_for "a structured module" do
    it { is_expected.to compile.with_all_deps }
    it { is_expected.to contain_class('simp_rsyslog') }
  end

  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        context "simp_rsyslog class without any parameters" do
          let(:params) {{ }}
          it_behaves_like "a structured module"
          it { is_expected.to contain_class('simp_rsyslog::local') }
          it {
            is_expected.to contain_rsyslog__rule__local('HH_simp_rsyslog_profile_local').with_rule(
              /\(\$programname == 'sudo'\) or \(\$programname == 'sudosh'\)/
            )
          }
          it { is_expected.to contain_rsyslog__rule__local('HH_simp_rsyslog_profile_local').with_stop_processing(true) }
          it { is_expected.not_to contain_class('simp_rsyslog::server') }
          it { is_expected.not_to contain_class('simp_rsyslog::forward') }
        end

        context "simp rsyslog class collecting all logs" do
          let(:params){{
            :collect_everything => true
          }}

          it_behaves_like "a structured module"
          it { is_expected.to contain_class('simp_rsyslog::local') }
          it { is_expected.to contain_rsyslog__rule__local('HH_simp_rsyslog_profile_local').with_rule("prifilt('*.*')") }
          it { is_expected.to contain_rsyslog__rule__local('HH_simp_rsyslog_profile_local').with_stop_processing(true) }
          it { is_expected.not_to contain_class('simp_rsyslog::server') }
          it { is_expected.not_to contain_class('simp_rsyslog::forward') }
        end

        context "simp_rsyslog class forwarding logs" do
          let(:params) {{
            :forward_logs => true,
            :log_servers  => ['1.2.3.4']
          }}
          it_behaves_like "a structured module"
          it { is_expected.to contain_class('simp_rsyslog::forward') }
          it {
            is_expected.to contain_rsyslog__rule__remote('99_simp_rsyslog_profile_remote').with_rule(
              /\(\$programname == 'sudo'\) or \(\$programname == 'sudosh'\)/
            )
          }
          it { is_expected.to contain_rsyslog__rule__remote('99_simp_rsyslog_profile_remote').with_dest_type('tcp') }
          it { is_expected.to contain_rsyslog__rule__remote('99_simp_rsyslog_profile_remote').with_stop_processing(false) }
        end

        context "simp_rsyslog class log server" do
          let(:params) {{
            :is_server => true
          }}
          it_behaves_like "a structured module"
          it { is_expected.to contain_class('simp_rsyslog::server') }
          it { is_expected.to contain_rsyslog__rule__local('10_00_default_boot') }
          it { is_expected.to contain_rsyslog__rule__local('10_00_default_kern') }
          it { is_expected.to contain_rsyslog__rule__local('10_00_default_mail') }
          it { is_expected.to contain_rsyslog__rule__local('10_00_default_cron') }
          it { is_expected.to contain_rsyslog__rule__local('10_00_default_emerg') }
          it { is_expected.to contain_rsyslog__rule__local('10_default_sudosh') }
          it { is_expected.to contain_rsyslog__rule__local('10_default_httpd_error') }
          it { is_expected.to contain_rsyslog__rule__local('11_default_httpd') }
          it { is_expected.to contain_rsyslog__rule__local('10_default_dhcpd') }
          it { is_expected.to contain_rsyslog__rule__local('10_default_puppet_agent_error') }
          it { is_expected.to contain_rsyslog__rule__local('11_default_puppet_agent') }
          it { is_expected.to contain_rsyslog__rule__local('10_default_puppetserver_error') }
          it { is_expected.to contain_rsyslog__rule__local('11_default_puppetserver') }
          it { is_expected.to contain_rsyslog__rule__local('10_default_audit') }
          it { is_expected.to contain_rsyslog__rule__local('10_default_slapd_audit') }
          it { is_expected.to contain_rsyslog__rule__local('10_default_iptables') }
          it { is_expected.to contain_rsyslog__rule__local('10_default_spool') }
          it { is_expected.to contain_rsyslog__rule__local('17_default_security_relevant_logs') }
          it { is_expected.to contain_rsyslog__rule__local('19_default_message') }
          it { is_expected.to contain_rsyslog__rule__local('30_default_catchall') }
          it { is_expected.not_to contain_rsyslog__rule__local('30_default_drop') }
          it { is_expected.to contain_class('logrotate') }
          it { 
            if facts[:operatingsystemmajrelease].to_s <= '6'
               expected_cmd ='/sbin/service rsyslog restart > /dev/null 2>&1 || true'
            else
               expected_cmd ='/usr/bin/systemctl restart rsyslog > /dev/null 2>&1 || true'
            end
            is_expected.to contain_logrotate__rule('simp_rsyslog_server_profile').with( {
                :lastaction => expected_cmd
            })
          }
        end

        context "simp_rsyslog class with everything enabled" do
          let(:params) {{
            :is_server            => true,
            :forward_logs         => true,
            :log_servers          => ['1.2.3.4'],
            :failover_log_servers => ['3.4.5.6'],
            :log_openldap         => true,
            :collect_everything   => true
          }}

          it_behaves_like "a structured module"
          it { is_expected.to contain_class('simp_rsyslog::server') }
        end
      end
    end
  end
end
