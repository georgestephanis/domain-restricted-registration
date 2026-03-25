<?php
/**
 * Plugin Name: Domain-Restricted Registration
 * Description: Restricts user registration to specific email domains and requires email confirmation before login.
 * Version:     1.1.0
 * Requires at least: 5.5
 * Requires PHP: 7.4
 * Author:      George Stephanis
 * License:     GPL-2.0-or-later
 *
 * Allowed rules are configured in Settings > General under "Allowed Registration Domains".
 * Each line is one rule; three formats are accepted:
 *
 *   example.com        — exact domain match
 *   .edu               — TLD/suffix match (any domain ending in .edu)
 *   /\.acme\.com$/i    — PCRE regex tested against the domain part only
 *
 * When at least one rule is configured, new registrants must use a matching email address.
 * They receive a "Confirm your email" message containing a password-set link, and cannot
 * log in (or use the REST API) until they click it. Leaving the rules field empty restores
 * default WordPress behaviour entirely.
 *
 * Note: Activation links expire after 24 hours (WordPress default). If a user does not
 * activate in time, a site admin can delete and re-register the account.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Option key storing the allowed-domain rules as a newline-separated string.
 * Each line is one rule (exact domain, .tld suffix, or /regex/).
 */
const DRR_DOMAINS_OPTION = 'drr_allowed_domains';

/** Option key storing the custom rejection error message (plain text). */
const DRR_MESSAGE_OPTION = 'drr_error_message';

/** User-meta key that marks an account as pending email confirmation. */
const DRR_META_KEY = 'drr_registration_pending';

// ---------------------------------------------------------------------------
// Hook registrations
// ---------------------------------------------------------------------------

// One-time migration from v1.0's single-domain string option.
add_action( 'init', 'drr_maybe_migrate' );

// Settings API — register options and add fields to Settings > General.
add_action( 'admin_init', 'drr_register_settings' );
add_action( 'admin_init', 'drr_add_settings_fields' );

// Validate email domain during the standard registration flow.
add_filter( 'registration_errors', 'drr_validate_email_domain', 10, 3 );

// Validate email domain during multisite network signup.
add_filter( 'wp_mu_validate_user_signup', 'drr_check_multisite_signup' );

// Intercept at priority 1 — fires BEFORE core's wp_send_new_user_notifications at priority 10.
add_action( 'register_new_user', 'drr_intercept_registration', 1 );

// Block login for accounts that haven't confirmed their email yet.
// Priority 30 fires AFTER core credential checks at priority 20.
add_filter( 'authenticate', 'drr_block_pending_login', 30, 3 );

// Block REST API access for pending accounts. Application passwords for the
// REST API bypass the authenticate filter entirely — they authenticate via the
// determine_current_user filter instead. rest_authentication_errors fires after
// that filter has resolved the current user, giving us a second interception point.
add_filter( 'rest_authentication_errors', 'drr_block_pending_rest_request' );

// Activate the account when the user sets their password via the confirmation link.
add_action( 'after_password_reset', 'drr_activate_account', 10, 2 );

// JS toggle — only outputs on the General Settings screen.
add_action( 'admin_footer-options-general.php', 'drr_enqueue_toggle_script' );

// ---------------------------------------------------------------------------
// Migration
// ---------------------------------------------------------------------------

/**
 * One-time migration from v1.0 which stored a single domain string in
 * 'drr_allowed_domain'. If that option exists and the new option has not yet
 * been written, carry the value forward and delete the old key.
 */
function drr_maybe_migrate(): void {
	$old = get_option( 'drr_allowed_domain', '' );
	if ( '' === $old ) {
		return;
	}

	// false means the new option has never been saved; don't overwrite if it has.
	if ( false !== get_option( DRR_DOMAINS_OPTION, false ) ) {
		return;
	}

	update_option( DRR_DOMAINS_OPTION, $old );
	delete_option( 'drr_allowed_domain' );
}

// ---------------------------------------------------------------------------
// Section 1: Settings registration
// ---------------------------------------------------------------------------

/**
 * Registers both plugin options with the general settings group so they are
 * saved automatically when the General Settings form is submitted.
 */
function drr_register_settings(): void {
	register_setting(
		'general',
		DRR_DOMAINS_OPTION,
		array(
			'type'              => 'string',
			'sanitize_callback' => 'drr_sanitize_rules',
			'default'           => '',
			'show_in_rest'      => false,
		)
	);

	register_setting(
		'general',
		DRR_MESSAGE_OPTION,
		array(
			'type'              => 'string',
			'sanitize_callback' => 'sanitize_textarea_field',
			'default'           => '',
			'show_in_rest'      => false,
		)
	);
}

/**
 * Parses, validates, and normalises the submitted rules into a newline-separated
 * string for storage.
 *
 * Accepts two input shapes:
 *
 *   Array (from the repeating-row UI):
 *     [ ['type' => 'domain'|'tld'|'regex', 'value' => '...'], ... ]
 *
 *   String (legacy textarea / migration path):
 *     "example.com\n.edu\n/regex/"
 *
 * Invalid entries are stripped and reported via a settings error.
 *
 * @param mixed $value Array from the repeating-row UI, or a legacy string.
 * @return string Newline-separated, validated rules ready for storage.
 */
function drr_sanitize_rules( $value ): string {
	// Normalise both input shapes into a flat array of raw rule strings.
	if ( is_array( $value ) ) {
		$lines = array();
		foreach ( $value as $row ) {
			if ( ! is_array( $row ) || empty( $row['type'] ) ) {
				continue;
			}
			$type  = sanitize_key( $row['type'] );
			$entry = trim( sanitize_text_field( $row['value'] ?? '' ) );
			if ( '' === $entry ) {
				continue;
			}

			switch ( $type ) {
				case 'domain':
					$lines[] = $entry;
					break;
				case 'tld':
					// Normalise: ensure exactly one leading dot.
					$lines[] = '.' . ltrim( $entry, '.' );
					break;
				case 'regex':
					// If the user entered a bare pattern without delimiters, wrap it.
					$lines[] = ( '/' === $entry[0] ) ? $entry : '/' . $entry . '/';
					break;
			}
		}
	} else {
		// Legacy textarea string or migration value.
		$lines = array_map( 'trim', explode( "\n", (string) $value ) );
	}

	$valid   = array();
	$invalid = array();

	foreach ( $lines as $line ) {
		if ( '' === $line ) {
			continue;
		}

		// Regex pattern: starts with /
		if ( '/' === $line[0] ) {
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( false === @preg_match( $line, '' ) ) {
				$invalid[] = $line;
			} else {
				$valid[] = $line; // Preserve original case/flags for regexes.
			}
			continue;
		}

		// TLD/suffix: starts with a dot.
		if ( '.' === $line[0] ) {
			$suffix = ltrim( $line, '.' );
			if ( preg_match( '/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i', $suffix ) ) {
				$valid[] = strtolower( $line );
			} else {
				$invalid[] = $line;
			}
			continue;
		}

		// Exact domain: must look like domain.tld (deliberately liberal).
		if ( preg_match( '/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i', $line ) ) {
			$valid[] = strtolower( $line );
		} else {
			$invalid[] = $line;
		}
	}

	if ( ! empty( $invalid ) ) {
		add_settings_error(
			DRR_DOMAINS_OPTION,
			'drr_invalid_rules',
			sprintf(
				/* translators: %s: comma-separated list of invalid rules */
				__( 'The following domain rules were invalid and have been removed: %s' ),
				implode( ', ', array_map( 'esc_html', $invalid ) )
			)
		);
	}

	return implode( "\n", $valid );
}

// ---------------------------------------------------------------------------
// Section 2: Core matching helper
// ---------------------------------------------------------------------------

/**
 * Returns the stored rules as an array, one rule per element.
 *
 * @return string[] Array of rule strings; empty array when no restriction is configured.
 */
function drr_get_rules(): array {
	$raw = get_option( DRR_DOMAINS_OPTION, '' );
	if ( '' === $raw ) {
		return array();
	}
	return array_values( array_filter( array_map( 'trim', explode( "\n", $raw ) ) ) );
}

/**
 * Returns true if the given email address is permitted to register.
 *
 * Returns true (allowed) if:
 *   - The email is not a valid address format — let core report the format error.
 *   - No rules are configured — restriction is disabled.
 *   - The domain part matches at least one configured rule.
 *
 * Rule matching (tested in order per rule):
 *   /regex/flags — PCRE matched against the domain part only.
 *   .tld         — suffix match: domain must end with this string.
 *   domain.com   — exact case-insensitive match.
 *
 * @param string $email The email address to test.
 * @return bool True if permitted, false if blocked.
 */
function drr_is_email_allowed( string $email ): bool {
	if ( ! is_email( $email ) ) {
		return true; // Malformed — not our job to reject it; let core handle it.
	}

	$rules = drr_get_rules();
	if ( empty( $rules ) ) {
		return true; // No restriction configured.
	}

	// Extract the domain portion after the last @.
	$domain = strtolower( substr( $email, strrpos( $email, '@' ) + 1 ) );

	foreach ( $rules as $rule ) {
		if ( '' === $rule ) {
			continue;
		}

		// Regex rule.
		if ( '/' === $rule[0] ) {
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( @preg_match( $rule, $domain ) ) {
				return true;
			}
			continue;
		}

		// TLD/suffix rule (e.g. ".edu").
		if ( '.' === $rule[0] ) {
			$suffix = strtolower( $rule );
			if ( substr( $domain, -strlen( $suffix ) ) === $suffix ) {
				return true;
			}
			continue;
		}

		// Exact domain match.
		if ( $domain === strtolower( $rule ) ) {
			return true;
		}
	}

	return false;
}

// ---------------------------------------------------------------------------
// Section 3: Settings fields (UI)
// ---------------------------------------------------------------------------

/**
 * Adds the two plugin settings fields to the default section of the General
 * settings page. WordPress renders these rows inside the existing table via
 * do_settings_fields('general','default').
 */
function drr_add_settings_fields(): void {
	add_settings_field(
		'drr_allowed_domains_field',
		__( 'Allowed Registration Domains' ),
		'drr_render_domains_field',
		'general',
		'default'
	);

	add_settings_field(
		'drr_error_message_field',
		__( 'Domain Restriction Error Message' ),
		'drr_render_message_field',
		'general',
		'default'
	);
}

/**
 * Parses a single stored rule string into a display-friendly array.
 *
 * @param string $rule A stored rule (e.g. "example.com", ".edu", "/regex/i").
 * @return array{type: string, value: string}
 */
function drr_parse_rule( string $rule ): array {
	if ( '' !== $rule && '/' === $rule[0] ) {
		return array( 'type' => 'regex', 'value' => $rule );
	}
	if ( '' !== $rule && '.' === $rule[0] ) {
		return array( 'type' => 'tld', 'value' => $rule );
	}
	return array( 'type' => 'domain', 'value' => $rule );
}

/**
 * Renders the repeating-row UI for the allowed-domain rules.
 *
 * Each row has a type dropdown (Exact Domain / TLD Suffix / Regex Pattern) and
 * a text input for the value. Rows can be removed individually, and new rows
 * are added via an "Add Rule" link. A <template> element is used for cloning.
 *
 * Input names use drr_allowed_domains[N][type] / drr_allowed_domains[N][value]
 * so that PHP receives an array that drr_sanitize_rules() can process.
 */
function drr_render_domains_field(): void {
	$rules = drr_get_rules();
	$option = esc_attr( DRR_DOMAINS_OPTION );
	?>
	<div id="drr-domain-wrapper">
		<table class="wp-list-table widefat fixed striped" id="drr-rules-table" style="max-width:600px;">
			<thead>
				<tr>
					<th style="width:160px;"><?php esc_html_e( 'Type' ); ?></th>
					<th><?php esc_html_e( 'Value' ); ?></th>
					<th style="width:60px;"></th>
				</tr>
			</thead>
			<tbody id="drr-rules-body">
			<?php foreach ( $rules as $index => $rule ) :
				$parsed = drr_parse_rule( $rule );
				?>
				<tr class="drr-rule-row">
					<td>
						<select name="<?php echo $option; ?>[<?php echo $index; ?>][type]" class="drr-rule-type">
							<option value="domain" <?php selected( $parsed['type'], 'domain' ); ?>><?php esc_html_e( 'Exact Domain' ); ?></option>
							<option value="tld"    <?php selected( $parsed['type'], 'tld' ); ?>><?php esc_html_e( 'TLD Suffix' ); ?></option>
							<option value="regex"  <?php selected( $parsed['type'], 'regex' ); ?>><?php esc_html_e( 'Regex Pattern' ); ?></option>
						</select>
					</td>
					<td>
						<input
							type="text"
							name="<?php echo $option; ?>[<?php echo $index; ?>][value]"
							value="<?php echo esc_attr( $parsed['value'] ); ?>"
							class="regular-text drr-rule-value"
						/>
					</td>
					<td>
						<button type="button" class="button-link drr-remove-row" aria-label="<?php esc_attr_e( 'Remove rule' ); ?>">&times;</button>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>

		<p><a href="#" id="drr-add-rule" class="button-link"><?php esc_html_e( '+ Add Rule' ); ?></a></p>

		<p class="description">
			<?php esc_html_e( 'If any rules are configured, only matching addresses may register and new accounts require email confirmation. Leave empty to allow all domains.' ); ?>
		</p>

		<template id="drr-rule-template">
			<tr class="drr-rule-row">
				<td>
					<select name="<?php echo $option; ?>[DRR_INDEX][type]" class="drr-rule-type">
						<option value="domain"><?php esc_html_e( 'Exact Domain' ); ?></option>
						<option value="tld"><?php esc_html_e( 'TLD Suffix' ); ?></option>
						<option value="regex"><?php esc_html_e( 'Regex Pattern' ); ?></option>
					</select>
				</td>
				<td>
					<input
						type="text"
						name="<?php echo $option; ?>[DRR_INDEX][value]"
						value=""
						class="regular-text drr-rule-value"
						placeholder="example.com"
					/>
				</td>
				<td>
					<button type="button" class="button-link drr-remove-row" aria-label="<?php esc_attr_e( 'Remove rule' ); ?>">&times;</button>
				</td>
			</tr>
		</template>
	</div>
	<?php
}

/**
 * Renders the textarea for the custom rejection error message.
 */
function drr_render_message_field(): void {
	$value = get_option( DRR_MESSAGE_OPTION, '' );
	?>
	<div id="drr-message-wrapper">
		<textarea
			id="<?php echo esc_attr( DRR_MESSAGE_OPTION ); ?>"
			name="<?php echo esc_attr( DRR_MESSAGE_OPTION ); ?>"
			rows="3"
			class="large-text"
		><?php echo esc_textarea( $value ); ?></textarea>
		<p class="description">
			<?php esc_html_e( 'Shown when registration is rejected due to a domain mismatch. Leave empty to use the default message.' ); ?>
		</p>
	</div>
	<?php
}

// ---------------------------------------------------------------------------
// Section 4: JS show/hide toggle
// ---------------------------------------------------------------------------

/**
 * Outputs inline scripts for the General Settings page:
 *
 *   1. Show/hide toggle — hides both DRR rows when "Anyone can register" is
 *      unchecked. On multisite the checkbox is absent, so this is a no-op and
 *      the fields stay visible (registration is network-controlled there).
 *
 *   2. Repeating-row management — handles "Add Rule", per-row remove buttons,
 *      and updates the input placeholder to match the selected rule type.
 */
function drr_enqueue_toggle_script(): void {
	?>
	<script>
	( function () {

		/* ── 1. Show/hide toggle ── */
		var checkbox = document.getElementById( 'users_can_register' );
		if ( checkbox ) {
			var wrapperIds = [ 'drr-domain-wrapper', 'drr-message-wrapper' ];
			var settingsRows = [];
			wrapperIds.forEach( function ( id ) {
				var el = document.getElementById( id );
				if ( el ) {
					var tr = el.closest( 'tr' );
					if ( tr ) settingsRows.push( tr );
				}
			} );

			if ( settingsRows.length ) {
				function toggleRows() {
					var display = checkbox.checked ? '' : 'none';
					settingsRows.forEach( function ( tr ) { tr.style.display = display; } );
				}
				toggleRows();
				checkbox.addEventListener( 'change', toggleRows );
			}
		}

		/* ── 2. Repeating-row management ── */

		var rulesBody = document.getElementById( 'drr-rules-body' );
		var addLink   = document.getElementById( 'drr-add-rule' );
		var template  = document.getElementById( 'drr-rule-template' );

		if ( ! rulesBody || ! addLink || ! template ) {
			return;
		}

		// Placeholders shown per rule type so the user knows what to enter.
		var placeholders = {
			domain : 'example.com',
			tld    : '.edu',
			regex  : '/\\.example\\.com$/i'
		};

		/**
		 * Updates the text input placeholder to match the selected type,
		 * and clears the value when the type changes so stale values don't
		 * confuse the sanitiser.
		 */
		function onTypeChange( select ) {
			var input = select.closest( 'tr' ).querySelector( '.drr-rule-value' );
			if ( input ) {
				input.placeholder = placeholders[ select.value ] || '';
			}
		}

		// Wire up type dropdowns for rows that already exist in the DOM.
		rulesBody.querySelectorAll( '.drr-rule-type' ).forEach( function ( select ) {
			select.addEventListener( 'change', function () { onTypeChange( this ); } );
		} );

		// Counter used for unique name indices on new rows.
		// Start past any indices already rendered by PHP.
		var nextIndex = rulesBody.querySelectorAll( '.drr-rule-row' ).length;

		// "Add Rule" link.
		addLink.addEventListener( 'click', function ( e ) {
			e.preventDefault();

			var clone = template.content.cloneNode( true );

			// Replace the DRR_INDEX placeholder in name attributes.
			clone.querySelectorAll( '[name]' ).forEach( function ( el ) {
				el.name = el.name.replace( 'DRR_INDEX', nextIndex );
			} );
			nextIndex++;

			// Wire up the type dropdown on the new row.
			var newSelect = clone.querySelector( '.drr-rule-type' );
			if ( newSelect ) {
				newSelect.addEventListener( 'change', function () { onTypeChange( this ); } );
				// Set initial placeholder.
				var newInput = clone.querySelector( '.drr-rule-value' );
				if ( newInput ) newInput.placeholder = placeholders[ newSelect.value ] || '';
			}

			rulesBody.appendChild( clone );
		} );

		// Remove buttons — use event delegation so dynamically added rows work.
		rulesBody.addEventListener( 'click', function ( e ) {
			if ( e.target.classList.contains( 'drr-remove-row' ) ) {
				e.preventDefault();
				var row = e.target.closest( 'tr' );
				if ( row ) row.remove();
			}
		} );

	}() );
	</script>
	<?php
}

// ---------------------------------------------------------------------------
// Section 5: Registration validation
// ---------------------------------------------------------------------------

/**
 * Validates that the submitted email address matches at least one configured rule.
 *
 * Hooked to 'registration_errors' (wp-includes/user.php:3565).
 *
 * @param WP_Error $errors               Existing registration errors.
 * @param string   $sanitized_user_login Sanitised username.
 * @param string   $user_email           Submitted email address.
 * @return WP_Error Original or augmented error object.
 */
function drr_validate_email_domain( WP_Error $errors, string $sanitized_user_login, string $user_email ): WP_Error {
	if ( empty( drr_get_rules() ) ) {
		return $errors; // No restriction configured — pass through.
	}

	if ( drr_is_email_allowed( $user_email ) ) {
		return $errors; // Address is permitted.
	}

	$errors->add( 'drr_domain_mismatch', drr_get_rejection_message() );

	return $errors;
}

/**
 * Validates the email domain during multisite network user signup.
 *
 * Hooked to 'wp_mu_validate_user_signup'. The filter receives and must return
 * a result array containing 'user_name', 'user_email', and 'errors' (WP_Error).
 *
 * @param array $result Signup result array.
 * @return array Modified result array.
 */
function drr_check_multisite_signup( array $result ): array {
	if ( empty( $result['user_email'] ) || empty( drr_get_rules() ) ) {
		return $result;
	}

	if ( ! drr_is_email_allowed( $result['user_email'] ) ) {
		$result['errors']->add( 'drr_domain_mismatch', drr_get_rejection_message() );
	}

	return $result;
}

/**
 * Returns the rejection error message to display when a domain is not permitted.
 *
 * Uses the admin-configured custom message if one has been set, otherwise falls
 * back to a generic default. The stored message is always plain text.
 *
 * @return string The error message, HTML-safe for use in WP_Error.
 */
function drr_get_rejection_message(): string {
	$custom = get_option( DRR_MESSAGE_OPTION, '' );
	if ( '' !== $custom ) {
		return esc_html( $custom );
	}
	return __( '<strong>Error:</strong> Registration is not allowed for your email domain.' );
}

// ---------------------------------------------------------------------------
// Section 6: Registration interception
// ---------------------------------------------------------------------------

/**
 * Fires at priority 1 on 'register_new_user', before core's
 * wp_send_new_user_notifications at priority 10.
 *
 * When domain restriction is active:
 *   1. Removes core's default dual-email notification so ours is the only one sent.
 *   2. Marks the account as pending email confirmation via user meta.
 *   3. Sends the admin a standard new-user notification.
 *   4. Sends the registrant a custom "Confirm your email" message.
 *
 * @param int $user_id Newly created user ID.
 */
function drr_intercept_registration( int $user_id ): void {
	if ( empty( drr_get_rules() ) ) {
		return; // No restriction active — leave default behaviour intact.
	}

	// Prevent core's default notification (which would send a second email to the user).
	remove_action( 'register_new_user', 'wp_send_new_user_notifications' );

	// Flag the account as unconfirmed.
	update_user_meta( $user_id, DRR_META_KEY, '1' );

	// Still notify the site admin of the new registration.
	wp_new_user_notification( $user_id, null, 'admin' );

	// Send the registrant their custom confirmation email.
	drr_send_confirmation_email( $user_id );
}

/**
 * Builds and sends a "Confirm your email address" message to a newly
 * registered user. The message contains a password-set link that doubles as
 * the account activation link.
 *
 * @param int $user_id Newly created user ID.
 */
function drr_send_confirmation_email( int $user_id ): void {
	$user = get_userdata( $user_id );
	if ( ! $user ) {
		return;
	}

	$key = get_password_reset_key( $user );
	if ( is_wp_error( $key ) ) {
		error_log( sprintf(
			'DRR: Could not generate activation key for user %d (%s): %s',
			$user_id,
			$user->user_email,
			$key->get_error_message()
		) );
		return;
	}

	/*
	 * Build the activation URL in the same format as core (pluggable.php:2382).
	 * The login= parameter comes before key= to avoid trailing-period issues
	 * in some email clients (see WordPress Trac #42957).
	 */
	$activation_url = network_site_url(
		'wp-login.php?action=rp&login=' . rawurlencode( $user->user_login ) . '&key=' . $key,
		'login'
	);

	$blogname = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );

	// Respect the user's preferred locale if set (matches core's approach in pluggable.php).
	$switched_locale = switch_to_user_locale( $user_id );

	/* translators: %s: site name */
	$subject = sprintf( __( '[%s] Confirm your email address' ), $blogname );

	$message  = sprintf(
		/* translators: %s: user's display name */
		__( 'Hi %s,' ),
		$user->display_name
	) . "\r\n\r\n";

	$message .= sprintf(
		/* translators: %s: site name */
		__( 'Thank you for registering on %s.' ),
		$blogname
	) . "\r\n\r\n";

	$message .= __(
		'To activate your account and set your password, visit the link below. This link expires in 24 hours.'
	) . "\r\n\r\n";

	$message .= $activation_url . "\r\n\r\n";

	$message .= __(
		'If you did not register for this site, you can safely ignore this email.'
	) . "\r\n";

	wp_mail( $user->user_email, $subject, $message );

	if ( $switched_locale ) {
		restore_previous_locale();
	}
}

// ---------------------------------------------------------------------------
// Section 7: Block login for unconfirmed accounts
// ---------------------------------------------------------------------------

/**
 * Returns a WP_Error for any user whose account has not yet been confirmed
 * via the activation link.
 *
 * Hooked to 'authenticate' at priority 30, after core's credential checks at
 * priority 20. Receives a resolved WP_User on successful credential check.
 * Returning WP_Error aborts authentication and triggers wp_login_failed.
 *
 * @param WP_User|WP_Error|null $user     Result from earlier authenticate handlers.
 * @param string                $username Submitted username (unused here).
 * @param string                $password Submitted password (unused here).
 * @return WP_User|WP_Error|null Unchanged $user, or a WP_Error if account is pending.
 */
function drr_block_pending_login( $user, string $username, string $password ) {
	// Pass through if authentication already failed for another reason.
	if ( is_wp_error( $user ) || null === $user ) {
		return $user;
	}

	if ( ! get_user_meta( $user->ID, DRR_META_KEY, true ) ) {
		return $user; // Account is active — no action needed.
	}

	return new WP_Error(
		'drr_account_pending',
		sprintf(
			/* translators: %s: the user's email address */
			__( '<strong>Error:</strong> Your account is not yet active. Please check your inbox at <strong>%s</strong> for the confirmation link.' ),
			esc_html( $user->user_email )
		)
	);
}

/**
 * Blocks REST API access for accounts that have not yet confirmed their email.
 *
 * Application passwords for the REST API authenticate via the determine_current_user
 * filter (wp-includes/default-filters.php:509 → wp_validate_application_password),
 * which calls wp_authenticate_application_password() directly and returns a user ID —
 * never passing through the authenticate filter where drr_block_pending_login lives.
 *
 * rest_authentication_errors fires after determine_current_user has resolved the
 * current user but before any REST route is dispatched, making it the correct
 * second interception point.
 *
 * @param WP_Error|true|null $result Existing authentication error, true (force auth), or null.
 * @return WP_Error|true|null Unchanged, or a WP_Error with HTTP 401 status.
 */
function drr_block_pending_rest_request( $result ) {
	// If another handler already set an error (or forced auth), respect it.
	if ( ! empty( $result ) ) {
		return $result;
	}

	$user = wp_get_current_user();
	if ( $user->exists() && get_user_meta( $user->ID, DRR_META_KEY, true ) ) {
		return new WP_Error(
			'drr_account_pending',
			__( 'Your account is not yet active. Please confirm your email address before using the API.' ),
			array( 'status' => 401 )
		);
	}

	return $result;
}

// ---------------------------------------------------------------------------
// Section 8: Account activation on password set
// ---------------------------------------------------------------------------

/**
 * Activates a pending account once the user has set their password via the
 * confirmation link. Fires via after_password_reset in wp-includes/user.php.
 *
 * This hook fires for all password resets, not just new registrations, so we
 * check for the pending meta flag before acting.
 *
 * @param WP_User $user     The user whose password was reset.
 * @param string  $new_pass The newly set password (not used here).
 */
function drr_activate_account( WP_User $user, string $new_pass ): void {
	if ( ! get_user_meta( $user->ID, DRR_META_KEY, true ) ) {
		return; // Not a pending registration reset — leave untouched.
	}

	delete_user_meta( $user->ID, DRR_META_KEY );

	// Clean up the "default password nag" core sets on registration, since the
	// user has now intentionally chosen their password.
	delete_user_meta( $user->ID, 'default_password_nag' );
}
