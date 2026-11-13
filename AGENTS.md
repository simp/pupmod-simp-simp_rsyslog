# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## What this module does

`simp-simp_rsyslog` is a SIMP **profile** module: an opinionated policy layer on
top of the `simp/rsyslog` component module. It does not configure the rsyslog
daemon directly — instead it decides *which* logs are security-relevant, *where*
they go (local disk, forwarded to remote log servers, or collected as a central
log server), and expresses those decisions as `rsyslog::rule::*` resources.

By default it only sets the system up as a **local** rsyslog logger with no
outside connectivity. Three orthogonal roles are switched on by boolean
parameters (`manifests/init.pp`), and each role is a separate contained
private class:

- **local** (`$log_local`, default `true`) — write security-relevant logs to
  the filesystem (`$local_target`, default `/var/log/secure`).
- **forward** (`$forward_logs`, default `false`) — ship security-relevant logs
  to remote log servers in parallel, with optional failover servers.
- **server** (`$is_server`, default `false`) — act as a centralized log
  collection server, sorting inbound logs into per-host files.

The roles are independent and composable: a host can be a local logger *and* a
forwarder *and* a server at once. See the WARNING in the class docstring
(`manifests/init.pp`): if a log server lists itself (or its aliases) in
`log_servers`/`failover_log_servers`, you can create an infinite log loop that
fills the server's disk within minutes — there is no foolproof detection of
this, only the runtime warning described below.

### Business logic

`simp_rsyslog` (`manifests/init.pp`) is the sole public class; the three
role classes are private (`assert_private()`). The public class computes the
`$security_relevant_logs` rule string once and the role classes consume it via
`$::simp_rsyslog::security_relevant_logs`.

**Computing `$security_relevant_logs` (`init.pp`).** This is the heart
of the profile:

- If `$collect_everything` is true, the rule is simply `prifilt('*.*')`
  (`init.pp`) — matches every log, overrides all other rules, meant for
  remote collection where all data is required.
- Otherwise it is
  `simp_rsyslog::format_options(simp_rsyslog::merge_hash_of_arrays($default_logs, $_openldap_logs, $log_collection))`
  (`init.pp`). This is the **log_collection deep-merge**:
  1. `$default_logs` (`init.pp`) is the built-in hash of arrays
     (`programs`, `facilities`, `msg_starts`, `msg_regex`) — the default set of
     security-relevant sources (aide, audit, sudo, IPT firewall messages, etc.).
  2. `$_openldap_logs` (`init.pp`) adds `slapd`/`local4.*` **only** when
     `$log_openldap` is true (those logs are very verbose).
  3. `$log_collection` is the user's Hiera contribution.
  These three hashes are combined by
  `simp_rsyslog::merge_hash_of_arrays` (`lib/puppet/functions/simp_rsyslog/merge_hash_of_arrays.rb`),
  which `deep_merge!`s so that arrays under the same key are **unioned**, not
  replaced. The merged hash is then rendered into a single rsyslog Expression
  Filter string by `simp_rsyslog::format_options`
  (`lib/puppet/functions/simp_rsyslog/format_options.rb`).

**`simp_rsyslog::format_options` (`format_options.rb`).** Turns the hash
of arrays into one rsyslog 7 `if`-expression, ORing every entry together. Each
key maps to a fixed wrapper: `programs` → `($programname == '…')`, `facilities`
→ `prifilt('…')`, `msg_starts` → `($msg startswith '…')`, `msg_regex` →
`re_match($msg, '…')` (`format_options.rb`). Two guardrails: every
`facilities` entry **must** contain a `.` (`facility.priority`) or it raises
(`format_options.rb`); and if nothing produced output it raises "Did not find any valid content in the passed Options" (`format_options.rb`). Note `priorities` is a
documented `@option` on the public class but is **not** in `valid_options`, so
it is silently dropped by this function.

**`simp_rsyslog::local` (`manifests/local.pp`).** Drops duplicate `audispd`
messages (audit already writes them to `/var/log/audit`) via a `stop` rule
(`local.pp`), then writes a *residual* security-log rule
(`local.pp`) to `$::simp_rsyslog::local_target`. The `$order` parameter
(default `ZZ_0`) is carefully chosen to run **after** server rules (`1*`/`3*`)
and other SIMP module client rules (`XX_*`/`YY_*`) but **before** rsyslog's
`ZZ_default.conf` (`local.pp`). Note the residual rule uses its own
hardcoded `$_residual_logs`, not the merged `$security_relevant_logs`.

**`simp_rsyslog::forward` (`manifests/forward.pp`).** Fails the compile if
`$::simp_rsyslog::log_servers` is empty (`forward.pp`). If the host is
also a server and `$enable_warning` is true, emits the log-loop warning
(`forward.pp`). Declares a single `rsyslog::rule::remote`
(`forward.pp`) forwarding `$security_relevant_logs` to all `log_servers`
in parallel, with `failover_log_servers`, `dest_type` (default `tcp`),
`stop_processing`, and TLS `permitted_peers`.

**`simp_rsyslog::server` (`manifests/server.pp`).** A big flag-driven ruleset
that sorts inbound logs into per-host `dyna_file`s under `$logdir`
(default `/var/log/hosts`, keyed by `$dyna_key` = `%HOSTNAME%`). Each
`process_*_rules` boolean (all default `true`) toggles one
`rsyslog::rule::local`. Rule name prefixes encode processing order
(`server.pp`): `10_*`/`11_*` specific rules first, `17_*` catch-all for
security-relevant logs, `19_*` messages, `30_*` catchall/drop last. If
`$server_conf` is set, all built-in rules are skipped and that raw string is
used verbatim with no sanity checking (`server.pp`). `$enable_catchall`
(default `true`) sends anything unmatched to `catchall.log`; if false and
`$stop_processing`, unmatched logs are dropped to `~` instead
(`server.pp`). When `$add_logrotate_rule` is true (default), it asserts
the optional `simp/logrotate` dependency and adds a logrotate rule
(`server.pp`).

### Gotchas / non-obvious details

- **This is a profile, not a component.** It emits `rsyslog::rule::*` resources
  and `include 'rsyslog'` (`init.pp`); it never touches rsyslog config
  primitives directly. To change daemon-level behavior (TLS, listeners) you set
  parameters on the `rsyslog` class, not here (`init.pp`).
- **`log_collection` merges; `default_logs` replaces.** Setting
  `simp_rsyslog::default_logs` overrides *all* built-in defaults. To *add*
  entries, use `simp_rsyslog::log_collection` — it is deep-merged (unioned) into
  the defaults (`init.pp`, `data/common.yaml`). The Hiera merge behavior is
  pinned by `lookup_options` (see the seam section).
- **Log-forwarding loops are silent and destructive.** There is no foolproof
  detection that a log server appears in its own `log_servers` list
  (`init.pp`). The only guard is the runtime warning in `forward.pp`,
  emitted only when the host is both a server and a forwarder; disable it with
  `$enable_warning = false`.
- **`facilities` entries must contain a `.`** or `format_options` raises at
  compile (`format_options.rb`). Use the `facility.priority` form
  (e.g. `authpriv.*`).
- **The `priorities` option is documented but silently ignored** —
  `format_options` has no `priorities` handler (`format_options.rb`),
  though the public class and the function both advertise the `@option`.
- **The local residual rule is hardcoded**, independent of the merged
  `$security_relevant_logs` (`local.pp`) — editing `log_collection` does
  not change what `simp_rsyslog::local` writes.
- **`$collect_everything` overrides everything** — when true, every other rule
  distinction is discarded in favor of `prifilt('*.*')` (`init.pp`). Because it redefines `$security_relevant_logs` globally, it affects both forwarding (`forward.pp`) **and** the server role's local `17_default_security_relevant_logs` rule (`server.pp`), so it is not safe to treat as forwarding-only on servers.
- **`simp/logrotate` is optional, not required.** The server role calls
  `simplib::assert_optional_dependency($module_name, 'simp/logrotate')` at
  `manifests/server.pp` before `include 'logrotate'`, so the dependency is
  only enforced when `$add_logrotate_rule` is true.

## The `simp_options` / `simplib::lookup` seam

This module routes two SIMP feature toggles through
`simplib::lookup('simp_options::*', { 'default_value' => … })` rather than
assuming `simp_options` is included. Both calls are parameter defaults in
`manifests/init.pp`:

| File | Key | `default_value` |
|------|-----|-----------------|
| `init.pp` | `simp_options::syslog::log_servers` | `[]` |
| `init.pp` | `simp_options::syslog::failover_log_servers` | `[]` |

Keep routing SIMP feature toggles through this seam with an explicit default,
rather than assuming `simp_options` is present in the catalog.

## Dependencies

Module dependencies (from `metadata.json`):

- `simp/rsyslog` `>= 7.6.0 < 9.0.0` — the component module this profile drives
  (provides `rsyslog`, `rsyslog::server`, and the `rsyslog::rule::*` defines).
- `simp/simplib` `>= 4.9.0 < 5.0.0` — provides `simplib::lookup` and
  `simplib::assert_optional_dependency`.
- `puppetlabs/stdlib` `>= 8.0.0 < 10.0.0`.

Optional dependency (from `metadata.json` `simp.optional_dependencies`):

- `simp/logrotate` `>= 6.5.0 < 7.0.0` — used only by the server role when
  `$add_logrotate_rule` is true; enforced at runtime with
  `simplib::assert_optional_dependency($module_name, 'simp/logrotate')`
  (`manifests/server.pp`).

Runtime requirement (from `metadata.json` `requirements`): `puppet
>= 7.0.0 < 9.0.0`. This is an older baseline. (SIMP is migrating
Puppet → OpenVox; when `metadata.json` switches this to `openvox`, update this
line to match.)

Supported OS matrix (from `metadata.json`): CentOS 7/8/9; RedHat 7/8/9;
OracleLinux 7/8/9; Rocky 8/9; AlmaLinux 8/9.

## Repository layout

- `manifests/init.pp` — the public `simp_rsyslog` class; computes
  `$security_relevant_logs` and contains the enabled role classes.
- `manifests/local.pp` — private `simp_rsyslog::local` role
  (`assert_private()` at `local.pp`).
- `manifests/forward.pp` — private `simp_rsyslog::forward` role
  (`assert_private()` at `forward.pp`).
- `manifests/server.pp` — private `simp_rsyslog::server` role
  (`assert_private()` at `server.pp`).
- `lib/puppet/functions/simp_rsyslog/format_options.rb` — renders the merged
  log hash into a single rsyslog Expression Filter string.
- `lib/puppet/functions/simp_rsyslog/merge_hash_of_arrays.rb` — deep-merges
  (unions) the default, openldap, and user log hashes.
- `data/common.yaml` — module data; sets `lookup_options` so that
  `simp_rsyslog::log_collection` is **deep**-merged across the Hiera hierarchy.
- `metadata.json` — deps, optional deps, OS matrix, Puppet requirement.
- No `types/` or `templates/` — this module has no custom data types or
  templates; the only Ruby is the two functions above.

## Common commands

```sh
# Install dependencies
bundle install

# Run all unit tests
bundle exec rake spec

# Puppet lint
bundle exec rake lint

# Ruby lint
bundle exec rake rubocop

# Regenerate REFERENCE.md from puppet-strings docstrings
puppet strings generate --format markdown --out REFERENCE.md

# Run a beaker acceptance suite manually (not run in CI)
bundle exec rake beaker:suites[default]
```

The tested Puppet range is `>= 7 < 9` (`Gemfile`); the `Gemfile` installs the
**puppet** gem only via `gem 'puppet', puppet_version` (`Gemfile`) — there is
no OpenVox gem here yet. Relevant gem pins: `rubocop ~> 1.88.0` (`Gemfile`),
`puppetlabs_spec_helper ~> 8.0.0` (`Gemfile`), `simp-rake-helpers ~> 5.24.0`
(`Gemfile`), `simp-beaker-helpers ~> 2.0.0` (`Gemfile`).
`spec/spec_helper.rb` requires `puppetlabs_spec_helper/module_spec_helper`.

**CI:** the workflow runs only the standard six jobs — there is **no acceptance
job**. The two shipped beaker nodesets (`spec/acceptance/nodesets/default.yml`
and `oel.yml`) are for running acceptance manually.

## Conventions

- **Keep the profile/component split.** This module decides policy and emits
  `rsyslog::rule::*` resources; it should not reach into rsyslog daemon config.
  Daemon-level settings belong on the `rsyslog` class.
- **Additive log config goes through `log_collection`**, which is deep-merged;
  reserve `default_logs` for wholesale replacement. Preserve the `lookup_options`
  deep-merge in `data/common.yaml` if you touch module data.
- **Keep the role classes private.** `local`, `forward`, and `server` all call
  `assert_private()`; they are meant to be `contain`ed from the public class,
  not included directly.
- **Route SIMP toggles through the `simplib::lookup('simp_options::*', …)` seam**
  with an explicit `default_value`, as the two `log_servers` parameters do.
- **Guard optional integrations** (`simp/logrotate`) with
  `simplib::assert_optional_dependency` before `include`, as the server role
  does — don't hard-`include` optional modules.
- Preserve the `@summary` / `@param` / `@option` puppet-strings docstrings —
  they drive `REFERENCE.md`. Regenerate `REFERENCE.md` after changing docs or
  parameters.
- Match the existing 2-space Puppet indentation and aligned-arrow parameter
  style used in the manifests.
