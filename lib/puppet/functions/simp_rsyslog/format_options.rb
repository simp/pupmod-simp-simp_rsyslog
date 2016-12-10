# Formats a passed log options hash into a form that is appropriate for an
# Expression Filter-based Rsyslog 7 rule.
#
# @see https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/System_Administrators_Guide/s1-basic_configuration_of_rsyslog.html Basic Configuration of Rsyslog
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
Puppet::Functions.create_function(:'simp_rsyslog::format_options') do
  # @param opts
  #   The options hash.
  #
  #   * All entries will be combined with a logical ``OR``
  #   * **NOTE** Only the documented Hash keys will be respected
  #
  # @option options [Array[String]] 'programs' logged daemon names
  # @option options [Array[String]] 'facilities' syslog facilities
  # @option options [Array[String]] 'priorities' syslog priorities
  # @option options [Array[String]] 'msg_starts' strings the message starts with
  # @option options [Array[String]] 'msg_regex' regular exprssion match on the message
  #
  # @return [String]
  #   A formatted entry suitable for injecting into an ``if`` statement in
  #   Rsyslog 7
  #
  dispatch :format_options do
    param 'Hash', :opts
  end

  def format_options(opts)
    valid_options = {
      'programs'   => {
        :start => '($programname == ',
        :end   => ')'
      },
      'facilities' => {
        :start => 'prifilt(',
        :end   => ')'
      },
      'msg_starts' => {
        :start => '($msg startswith ',
        :end   => ')'
      },
      'msg_regex'  => {
        :start => 're_match($msg, ',
        :end   => ')'
      }
    }

    return_str = []

    Array(opts['facilities']).each do |facility|
      unless facility.include?('.')
        fail('All facility entries must be of the form "facility.priority"')
      end
    end

    valid_options.keys.each do |opt|
      Array(opts[opt]).each do |value|
        return_str << valid_options[opt][:start] + "'" + value + "'" + valid_options[opt][:end]
      end
    end

    if return_str.empty?
      fail('Did not find any valid content in the passed Options')
    end

    return return_str.join(' or ')
  end
end
