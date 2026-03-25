# Domain-Restricted Registration

[![Try in WordPress Playground](https://img.shields.io/badge/Try%20in-WordPress%20Playground-3858e9?logo=wordpress)](https://playground.wordpress.net/?blueprint-url=https://raw.githubusercontent.com/georgestephanis/domain-restricted-registration/trunk/.github/blueprint.json)

A WordPress plugin that restricts user registration to a single email domain and requires new accounts to confirm their email address before they can log in.

## Features

- **Domain restriction** — only email addresses matching the configured domain (e.g. `company.com`) can register.
- **Email confirmation** — new registrants receive a confirmation email containing a password-set link. Login is blocked until they click it.
- **REST API protection** — pending accounts are also blocked from the REST API, including application password authentication.
- **Inline DNS validation** — on the settings screen, the domain field checks the entered value against DNS in real time using the Google DNS-over-HTTPS API and shows a checkmark or warning.
- **Misconfiguration warning** — if a domain is saved but "Anyone can register" is disabled, an inline warning appears with a one-click link to enable registration.
- **Zero footprint when unconfigured** — leaving the domain field empty restores default WordPress behaviour completely.

## Requirements

- WordPress 5.5 or later
- PHP 7.4 or later

## Installation

1. Copy the `domain-restricted-registration` folder into `wp-content/plugins/`.
2. Activate the plugin from **Plugins › Installed Plugins**.
3. Go to **Settings › General**.
4. Enable **Anyone can register** under the Membership section.
5. Enter your domain in the **Limit Registration Domain** field (e.g. `company.com`).
6. Save changes.

## Configuration

All configuration is on **Settings › General**, in the Membership section.

| Field | Description |
|---|---|
| **Limit Registration Domain** | The domain users must register with. Leave empty to disable all restrictions. Do not include the `@` sign. |

## How registration works

1. A visitor submits the registration form with an email address.
2. If the email's domain doesn't match the configured domain, registration is rejected with a clear error message.
3. If it matches, the account is created and the visitor receives a **"Confirm your email address"** message containing a password-set link. The account is marked as pending.
4. Until the link is clicked, any login attempt — including via the REST API with application passwords — is blocked.
5. The visitor clicks the link, sets a password, and the account is activated. They can then log in normally.

> **Note:** Activation links expire after 24 hours (the WordPress default for password reset keys). If a user misses the window, a site administrator can delete their account so they can re-register, or manually remove the `drr_registration_pending` user meta to allow a standard password reset.

## Development

### Requirements

- [Composer](https://getcomposer.org/)

### Setup

```bash
composer install
```

### Linting

```bash
composer lint        # Run phpcs
composer lint-fix    # Run phpcbf (auto-fix)
```

The project uses the [WordPress Coding Standards](https://github.com/WordPress/WordPress-Coding-Standards) via WPCS 3.x. Configuration is in `.phpcs.xml.dist`.

## Licence

GPL-2.0-or-later — see [LICENSE](https://www.gnu.org/licenses/gpl-2.0.html).
