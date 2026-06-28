require 'beaker-rspec'
require 'tmpdir'
require 'yaml'
require 'simp/beaker_helpers'
include Simp::BeakerHelpers

# Returns true if the host can exercise netfilter packet logging (the
# iptables/firewalld LOG target that produces the "TYPE=8" ICMP entries the
# firewall-collection examples assert on).
#
# Under containerized runtimes (docker/podman, and especially the rootless
# podman + seccomp runtime used in CI) the host shares the read-only kernel
# netfilter stack of the container host: emitting kernel firewall log
# messages for inter-host pings is not permitted (and inter-container ICMP
# does not traverse the host's LOG rules the same way it does on a VM).
# In that case the firewall-log examples cannot pass for reasons unrelated
# to this module, so callers should `skip` them. On a full VM (vagrant)
# this returns true and the examples run for real.
#
# Detection is based on the hypervisor that provisioned the SUT rather than
# a live iptables probe: a privileged local docker daemon will happily
# accept a LOG rule yet still not log inter-container ICMP, so probing the
# rule is misleading. The hypervisor is an unambiguous, side-effect-free
# signal.
def firewall_logging_supported?(host)
  hypervisor = host[:hypervisor].to_s
  !['docker', 'podman'].include?(hypervisor)
end

# Wait up to max_wait_seconds for a message to be logged on a host or fail
# @param [String] host Name of test server on which the log file resides
# @param [String] log Fully qualified path to log on the test server
# @param [String] message Message to search for within the test server's log
# @param [Float]  max_wait_seconds Maximum number of seconds to wait for the
#                                  message to be found in the log before failing
# @param [Float]  interval_sec Interval in seconds between log checks
#
# TODO move to Simp::BeakerHelpers
require 'timeout'
def wait_for_log_message(
  host,
  log,
  message,
  max_wait_seconds = (ENV['SIMPTEST_WAIT_FOR_LOG_MAX'] ? ENV['SIMPTEST_WAIT_FOR_LOG_MAX'].to_f : 60.0),
  interval_sec = (ENV['SIMPTEST_LOG_CHECK_INTERVAL'] ? ENV['SIMPTEST_LOG_CHECK_INTERVAL'].to_f : 1.0)
)
  result = nil
  Timeout.timeout(max_wait_seconds) do
    loop do
      result = on host, "grep '#{message}' #{log}", accept_all_exit_codes: true
      return if result.exit_code == 0
      sleep(interval_sec)
    end
  end
rescue Timeout::Error
  error_msg = "Failed to find '#{message}' in #{log} on #{host} within #{max_wait_seconds} seconds:\n"
  error_msg += "\texit_code = #{result.exit_code}\n"
  error_msg += "\tstdout = \"#{result.stdout}\"\n" unless result.stdout.nil? || result.stdout.strip.empty?
  error_msg += "\tstderr = \"#{result.stderr}\"" unless result.stderr.nil? || result.stderr.strip.empty?
  raise error_msg
end

unless ENV['BEAKER_provision'] == 'no'
  hosts.each do |host|
    # Install Puppet
    if host.is_pe?
      install_pe
    else
      install_puppet
    end
  end
end

RSpec.configure do |c|
  # ensure that environment OS is ready on each host
  fix_errata_on hosts

  # Detect cases in which no examples are executed (e.g., nodeset does not
  # have hosts with required roles)
  c.fail_if_no_examples = true

  # Readable test descriptions
  c.formatter = :documentation

  # Configure all nodes in nodeset
  c.before :suite do
    # Install modules and dependencies from spec/fixtures/modules
    copy_fixture_modules_to(hosts)

    # Generate and install PKI certificates on each SUT
    Dir.mktmpdir do |cert_dir|
      run_fake_pki_ca_on(default, hosts, cert_dir)
      hosts.each { |sut| copy_pki_to(sut, cert_dir, '/etc/pki/simp-testing') }
    end
  rescue StandardError, ScriptError => e
    # rubocop:disable Lint/Debugger
    raise e unless ENV['PRY']
    require 'pry'
    binding.pry
    # rubocop:enable Lint/Debugger
  end
end
