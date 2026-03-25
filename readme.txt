=== Domain-Restricted Registration ===
Contributors: georgestephanis
Tags: registration, email, domain, restrict, confirmation
Requires at least: 5.5
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 2.0.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Restrict user registration to a single email domain and require email confirmation before login.

== Description ==

Domain-Restricted Registration adds one field to Settings > General that locks your site's registration form to a single email domain. Anyone who tries to register with a different domain is turned away with a clear error message.

When a domain is configured, new registrants also go through a lightweight email confirmation flow: they receive a "Confirm your email" message containing a password-set link, and cannot log in — or use the REST API — until they click it.

Leave the field empty and the plugin does nothing at all; default WordPress behaviour is fully restored.

**Features**

* Domain restriction — only email addresses matching the configured domain (e.g. `company.com`) can register.
* Email confirmation — new registrants must click a password-set link before their account is active.
* REST API protection — pending accounts are blocked from the REST API, including application password authentication.
* Inline DNS validation — the settings field checks the entered domain against DNS in real time and shows a green checkmark or red warning.
* Misconfiguration warning — if a domain is saved but "Anyone can register" is disabled, an inline notice appears with a one-click "Enable registration" link.
* Zero footprint when unconfigured — leaving the domain field empty restores default WordPress behaviour completely.

== Installation ==

1. Upload the `domain-restricted-registration` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the **Plugins** menu in WordPress.
3. Go to **Settings › General**.
4. Make sure **Anyone can register** is checked under the Membership section.
5. Enter your allowed domain in the **Limit Registration Domain** field (e.g. `company.com`) — no `@` sign.
6. Click **Save Changes**.

== Frequently Asked Questions ==

= Does the plugin work if "Anyone can register" is turned off? =

No. The domain restriction and email confirmation only apply to the WordPress registration flow. If open registration is disabled, nobody can register regardless of this plugin. The settings field will show an inline warning if you have a domain configured but registration is disabled, with a link to enable it.

= What happens if a user doesn't click the activation link in time? =

WordPress password reset keys expire after 24 hours. If a registrant misses the window, their account exists but is permanently blocked. A site administrator can either delete the account (so the user can re-register) or remove the `drr_registration_pending` user meta directly, which will allow the user to request a standard password reset.

= Does this block the REST API for unconfirmed accounts? =

Yes. Both cookie-based authentication and application password authentication are blocked for accounts with a pending confirmation, so an unconfirmed account cannot access any authenticated REST API endpoint.

= Will this work on multisite? =

The settings field appears on each site's own Settings > General page. The domain restriction will apply to that site's registration flow. Full network-level multisite registration (via `wp_mu_validate_user_signup`) is not currently supported.

= Does the plugin send any data to third parties? =

The settings screen makes a client-side request to the Google DNS-over-HTTPS API (`dns.google`) to validate that the entered domain exists in DNS. This request is made from the administrator's browser, not from the server, and only occurs on the Settings > General screen when the domain field loses focus. No data from registered users is sent anywhere.

== Changelog ==

= 2.0.0 =
* Simplified to single-domain support.
* Added inline DNS validation via Google DNS-over-HTTPS on the settings screen.
* Added inline misconfiguration warning with one-click "Enable registration" action link.
* Added REST API blocking for pending accounts via `rest_authentication_errors`.
* JS now relocates the settings row into the Membership section of the General settings page.
* WordPress Coding Standards compliance via WPCS 3.x / phpcs.

= 1.0.0 =
* Initial release.
