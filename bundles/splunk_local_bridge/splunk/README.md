# splunk

This directory contains the local-mode Splunk configuration bundle.

Using this bundle to start local Splunk means the operator is representing that
they have reviewed and accepted the then-current Splunk General Terms,
available at:

- https://www.splunk.com/en_us/legal/splunk-general-terms.html

If there is a separately negotiated agreement with Splunk that expressly
supersedes those terms, that agreement governs instead. Otherwise, by
accessing or using Splunk software through this bundle, the operator is
agreeing to the Splunk General Terms posted at the time of access and use and
acknowledging their applicability to the Splunk software.

If the operator does not agree to the Splunk General Terms, they must not
download, start, access, or use the software.

This bundle is intended only for local, single-instance workflows. Existing
Splunk license limits still apply. It is not an endorsed path to multi-instance
or long-term deployment, it does not promise a seamless upgrade or migration
path, it does not guarantee all Splunk Enterprise capabilities in every license
mode, and it does not proxy or replace a direct O11y integration.

## Main Files

- [default.yml](default.yml)
  - standalone bootstrap
  - direct HEC configuration
  - local index contract
  - retention and runtime guardrails
  - restricted role definition
  - default namespace for the restricted user
- `apps/defenseclaw_local_mode/`
  - source for the local landing app
  - nav, macros, eventtypes, saved searches, and phase-based observability dashboards
  - experimental local-only banner text
- `build/`
  - generated app archive location
- [package_local_mode_app.sh](package_local_mode_app.sh)
  - packages the app source into `build/defenseclaw_local_mode.tgz`
- `ansible/create_local_user.yml`
  - creates or updates `defenseclaw_local_user`
  - assigns the restricted role
  - sets `defaultApp=defenseclaw_local_mode`

## Supported Pattern

This repo uses the native `docker-splunk` / `splunk-ansible` bootstrap path first:

- app installation uses `splunk.apps_location`
- config files are emitted from `default.yml`
- the remaining custom Ansible is limited to the restricted local user bootstrap

That is intentional. If a future change can be expressed through `docker-splunk` or `splunk-ansible` configuration, prefer that over new custom tasks.
