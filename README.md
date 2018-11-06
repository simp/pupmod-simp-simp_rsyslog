#pupmod-simp-simp_rsyslog

[![License](https://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/73/badge)](https://bestpractices.coreinfrastructure.org/projects/73)
[![Puppet Forge](https://img.shields.io/puppetforge/v/simp/simp_rsyslog.svg)](https://forge.puppetlabs.com/simp/simp_rsyslog)
[![Puppet Forge Downloads](https://img.shields.io/puppetforge/dt/simp/simp_rsyslog.svg)](https://forge.puppetlabs.com/simp/simp_rsyslog)
[![Build Status](https://travis-ci.org/simp/pupmod-simp-simp_rsyslog.svg)](https://travis-ci.org/simp/pupmod-simp-simp_rsyslog)

#### Table of Contents

1. [Description](#description)
2. [Setup - The basics of getting started with simp_rsyslog](#setup)
    * [What simp_rsyslog affects](#what-simp_rsyslog-affects)
3. [Usage - Configuration options and additional functionality](#usage)
4. [Reference - An under-the-hood peek at what the module is doing and how](#reference)
5. [Limitations - OS compatibility, etc.](#limitations)
6. [Development - Guide for contributing to the module](#development)
    * [Acceptance Tests - Beaker env variables](#acceptance-tests)

## Description

This module is a [SIMP](https://simp-project.com) Puppet profile for setting up
common Rsyslog configurations as supported by the SIMP ecosystem

### This is a SIMP module

This module is a component of the [System Integrity Management Platform](https://simp-project.com),
a compliance-management framework built on Puppet.

If you find any issues, they may be submitted to our
[bug tracker](https://simp-project.atlassian.net/).

This module is optimally designed for use within a larger SIMP ecosystem, but
it can be used independently:

 * When included within the SIMP ecosystem, security compliance settings will
   be managed from the Puppet server.
 * If used independently, all SIMP-managed security subsystems are disabled by
   default and must be explicitly opted into by administrators.  Please review
   the parameters in
   [`simp/simp_options`](https://github.com/simp/pupmod-simp-simp_options) for
   details.

## Setup

### What simp_rsyslog affects

This module provides configurations for both Rsyslog local and Rsyslog server
configurations.

## Usage

### Local Logging

To set up local logging, you can simply do the following:

```ruby
include '::simp_rsyslog'
```

The `$log_collection` `Hash` provides an `Rsyslog 7` compatible set of
filters that you wish to collect. These will be considered **security
relevant** and fed into `/var/log/secure` by default.

The `Hash` has the following format and all entries will be combined with a
logical `OR`.

```ruby
$log_collection = {
  'programs'   => [ <logged daemon names> ],
  'facilities' => [ <syslog facilities> ],
  'priorities' => [ <syslog priorities> ],
  'msg_starts' => [ <strings the message starts with> ],
  'msg_regex'  => [ <regular expression matches> ]
}
```

If you need something more complex than this, you will need to configure your
own rsyslog rules using the `::rsyslog::rule` defined type.

If you simply want to log **EVERYTHING** to your remote servers, set
`simp_rsyslog::collect_everything` to `true`.

If you do this, it is **highly recommended** that you set
`simp_rsyslog::log_local` to `false` so that you don't overwhelm your
filesystem.

---------------------------------------------------------------------------

 **NOTE**

 If you do not capture the `local6` syslog facility, you will lose a lot of
 SIMP-specific messaging

---------------------------------------------------------------------------

### Centralized Logging

While we highly recommend [using ELG](https://simp.readthedocs.io/en/master/user_guide/HOWTO/Central_Log_Collection/Logstash.html) for collecting your logs, we understand that this
is not practical for all situations.

If you wish to collect logs from remote hosts, you can do the following:

**Manifest:**

```ruby
include '::simp_rsyslog'
```

**Hieradata:**

```yaml
---
simp_rsyslog::is_server : true
```

This will set your system up as an Rsyslog server, using TLS which is capable
of collecting both TCP and UDP logs.

At this time, the version of Rsyslog that ships with EL systems cannot handle
both TLS and non-TLS TCP connections at the same time. When it can, we will
support this mode of log collection.

UDP logs will not be encrypted in transit but are supported for network device
compatibility.

### Log Forwarding

If you wish to set your system up to forward logs to a set of remote log
servers, in either the server or client case, you should use the following:

```yaml
simp_rsyslog::forward_logs: true
```
This will use the `$simp_options::syslog::log_servers` and
`$simp_options::syslog::failover_log_servers` variables to set the targets for
your logs. Alternatively, you can specify the targets in Hiera directly.

TLS and TCP connections will be used for log forwarding for security purposes.

------------------------------------------------------------------------

> **WARNING**
>
> Be **VERY** careful when setting your ``simp_rsyslog::log_servers`` and
> ``simp_rsyslog::failover_log_servers`` Arrays!
>
> There is **no** foolproof way to detect if you are setting your local log
> server as part of the Array. If you do this, you may end up with infinite log
> loops that fill your log server's disk space within minutes.
>
> **WARNING**

------------------------------------------------------------------------

## Reference

The full module reference can be found in the
[module docs](https://simp.github.io/pupmod-simp-simp_rsyslog) and in the local
`docs/` directory.

## Limitations

This is a SIMP Profile. It will not expose **all** options of the underlying
modules, only the ones that are conducive to a supported SIMP infrastructure.

If you need to do things that this module does not cover, you may need to
create your own profile or inherit this profile and extend it to meet your
needs.

SIMP Puppet modules are generally intended for use on Red Hat Enterprise Linux
and compatible distributions, such as CentOS. Please see the
[`metadata.json` file](./metadata.json) for the most up-to-date list of
supported operating systems, Puppet versions, and module dependencies.

## Development

Please read our [Contribution Guide](http://simp.readthedocs.io/en/master/contributors_guide/index.html).

If you find any issues, they can be submitted to our
[JIRA](https://simp-project.atlassian.net).

### Acceptance tests

This module includes [Beaker](https://github.com/puppetlabs/beaker) acceptance
tests using the SIMP [Beaker Helpers](https://github.com/simp/rubygem-simp-beaker-helpers).
By default the tests use [Vagrant](https://www.vagrantup.com/) with
[VirtualBox](https://www.virtualbox.org) as a back-end; Vagrant and VirtualBox
must both be installed to run these tests without modification. To execute the
tests run the following:

```shell
bundle install
bundle exec rake beaker:suites
```

Please refer to the [SIMP Beaker Helpers documentation](https://github.com/simp/rubygem-simp-beaker-helpers/blob/master/README.md)
for more information.
