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

  let(:manifest) {
    <<-EOS
      include 'simp_rsyslog'
    EOS
  }

  hosts_with_role(hosts, 'client').each do |host|
    it 'should configure the system without errors' do
      apply_manifest_on(host, manifest, :catch_failures => true)
    end

    it 'should configure the system idempotently' do
      apply_manifest_on(host, manifest, :catch_changes => true)
    end

    it 'should collect security relevant log files from local6 into /var/log/secure' do
      on(host, 'logger -p local6.warn -t test_msg LOGGERSECURECHECK')
      sleep(1)

      check = on(host, 'grep -l LOGGERSECURECHECK /var/log/secure').stdout.strip

      expect(check).to eq('/var/log/secure')
    end
  end
end
