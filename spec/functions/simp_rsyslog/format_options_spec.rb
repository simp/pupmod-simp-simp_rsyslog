#!/usr/bin/env ruby -S rspec
require 'spec_helper'

describe 'simp_rsyslog::format_options' do
  context 'with valid parameters' do
    it {
      is_expected.to run.with_params({ 'programs' => ['foo'] }).and_return(%{($programname == 'foo')})
    }

    it {
      is_expected.to run.with_params(
        {
          'programs' => ['foo', 'bar'],
        }
      ).and_return(
        %{($programname == 'foo') or ($programname == 'bar')}
      )
    }

    it {
      is_expected.to run.with_params(
        {
          'programs' => ['foo1', 'bar1'],
          'facilities' => ['foo2.*', 'bar2.*'],
          'msg_starts' => ['foo4', 'bar4'],
          'msg_regex' => ['$foo5', '^.*bar5$']
        }
      ).and_return(
        [
          %{($programname == 'foo1') or ($programname == 'bar1')},
          %{prifilt('foo2.*') or prifilt('bar2.*')},
          %{($msg startswith 'foo4') or ($msg startswith 'bar4')},
          %{re_match($msg, '$foo5') or re_match($msg, '^.*bar5$')}
        ].join(' or ')
      )
    }
  end

  context 'with bad parameters' do
    it {
      is_expected.to run.with_params({}).and_raise_error(/not find any valid content/)
    }

    it {
      is_expected.to run.with_params({'foo' => ['bar']}).and_raise_error(/not find any valid content/)
    }
  end
end
