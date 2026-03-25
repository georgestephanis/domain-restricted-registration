# Domain-Restricted Registration — Claude Context

## What this plugin does

Restricts WordPress user registration to a single configured email domain and requires registrants to confirm their email address before they can log in. When no domain is configured the plugin is entirely inert and default WordPress behaviour is preserved.

## File structure

```
domain-restricted-registration/
├── domain-restricted-registration.php   # Entire plugin — single file
├── composer.json                        # Dev dependencies (phpcs, wpcs)
├── composer.lock
├── .phpcs.xml.dist                      # Coding standards config
├── vendor/                              # Composer-managed, not committed
├── CLAUDE.md                            # This file
├── README.md                            # GitHub readme
└── readme.txt                           # WordPress.org readme
```

## Key constants

| Constant | Value | Purpose |
|---|---|---|
| `DRR_OPTION_KEY` | `drr_allowed_domain` | Stores the allowed domain string (e.g. `"example.com"`). Empty = disabled. |
| `DRR_META_KEY` | `drr_registration_pending` | User meta flag set on new accounts; cleared when the user sets their password via the activation link. |

## Settings

One option stored in the `general` options group (saves automatically with the General Settings form):

- **`drr_allowed_domain`** — plain string, e.g. `automattic.com`. Sanitised through `drr_sanitize_domain()` which lowercases, strips a leading `@`, and validates format with a liberal regex. Empty = no restriction.

The field label is **"Limit Registration Domain"** and it appears in the **Membership** section of **Settings > General**. Because WordPress renders Settings API fields for the `general` page via `do_settings_fields('general','default')` at the bottom of `options-general.php`, a JS snippet in `drr_admin_scripts()` uses `insertAdjacentElement('afterend')` to move the `<tr>` into the DOM right after the "New User Default Role" row.

## Hook map

| Hook | Priority | Function | Purpose |
|---|---|---|---|
| `admin_init` | 10 | `drr_register_setting` | Register `drr_allowed_domain` with the Settings API |
| `admin_init` | 10 | `drr_add_settings_field` | Add the field to Settings > General |
| `registration_errors` | 10 | `drr_validate_email_domain` | Reject non-matching domains at registration time |
| `register_new_user` | **1** | `drr_intercept_registration` | Fires before core's `wp_send_new_user_notifications` at priority 10; removes that default, sets pending meta, sends admin notification, sends custom confirmation email |
| `authenticate` | **30** | `drr_block_pending_login` | Fires after core credential checks at priority 20; blocks login for users with pending meta |
| `rest_authentication_errors` | 10 | `drr_block_pending_rest_request` | Blocks REST API access for pending users (application passwords bypass `authenticate` entirely via `determine_current_user`) |
| `after_password_reset` | 10 | `drr_activate_account` | Deletes pending meta when user sets password via the activation link |
| `admin_footer-options-general.php` | 10 | `drr_admin_scripts` | Inline JS: DOM relocation, misconfiguration warning, DNS validation |
| `admin_post_drr_enable_registration` | 10 | `drr_handle_enable_registration` | Handles nonce-protected "Enable registration" action link |

## Registration flow (domain configured)

1. User submits the registration form.
2. `drr_validate_email_domain()` checks the domain part of the submitted email against `drr_allowed_domain`. Mismatch → `WP_Error` added, registration aborted.
3. On match, WordPress core calls `wp_create_user()` and then fires `register_new_user`.
4. `drr_intercept_registration()` (priority 1) runs first:
   - Calls `remove_action('register_new_user', 'wp_send_new_user_notifications')` to suppress the default dual email before it fires at priority 10.
   - Sets `drr_registration_pending = '1'` on the new user.
   - Calls `wp_new_user_notification($user_id, null, 'admin')` to still notify the admin.
   - Calls `drr_send_confirmation_email()` which uses `get_password_reset_key()` to build a `wp-login.php?action=rp&login=…&key=…` URL and mails it to the registrant.
5. User clicks the link → sets a password → `after_password_reset` fires → `drr_activate_account()` deletes `drr_registration_pending` and `default_password_nag`.
6. User logs in normally.

## Login blocking

- **`authenticate` filter (priority 30):** If credentials are valid but `drr_registration_pending` meta is set, returns a `WP_Error` instead of the `WP_User`. This also triggers `wp_login_failed`.
- **`rest_authentication_errors` filter:** Checks `wp_get_current_user()` after `determine_current_user` has resolved it (application passwords never pass through `authenticate`). Returns a `WP_Error` with HTTP 401 if pending meta is set.

## Admin UI (JS behaviour on Settings > General)

All JS is output inline by `drr_admin_scripts()` hooked to `admin_footer-options-general.php`.

**Row relocation:** Finds `#drr-domain-wrapper`, walks up to its `<tr>`, then inserts it after the `<tr>` containing `#default_role`. This places the field visually inside the Membership block despite being rendered at the bottom of the page by the Settings API.

**Misconfiguration warning (`#drr-registration-warning`):** A hidden `notice notice-warning inline` div rendered in PHP (containing the nonce-protected enable-registration URL). JS shows it whenever the domain input has a value AND `#users_can_register` is unchecked. Updates reactively on `change` of the checkbox and `input` events on the domain field.

**DNS validation:** On `focusout` of the domain input, fetches `https://dns.google/resolve?name=DOMAIN&type=A` (Google DNS-over-HTTPS JSON API). Shows a green checkmark for any non-NXDOMAIN response, a red warning for NXDOMAIN (status 3), and silently hides on network error. Skips the request if the value hasn't changed since the last check (`lastChecked` guard).

## Code standards

- **Linter:** `composer lint` (`vendor/bin/phpcs`)
- **Auto-fixer:** `composer lint-fix` (`vendor/bin/phpcbf`)
- **Standard:** WordPress + PHPCSUtils + PHPCSExtra (WPCS 3.x)
- **Config:** `.phpcs.xml.dist`
- **Suppressions:** `ShortPrefixPassed` excluded (drr/DRR is intentional), `UnusedFunctionParameter` excluded for the plugin file (hook callbacks must declare all positional params), `error_log` suppressed inline with explanation.
- **Text domain:** `domain-restricted-registration` on all i18n calls.

## Known limitations / future work

- Activation links expire after 24 hours (WordPress default for password reset keys). If a user misses the window they must be deleted and re-registered, or an admin must manually delete the `drr_registration_pending` user meta to let them attempt a standard password reset.
- No resend-activation flow.
- Single domain only — no multiple domains, wildcards, or regex. If multi-domain support is needed, this would require converting `drr_allowed_domain` from a scalar to a list and updating the validation logic accordingly.
