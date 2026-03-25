<?php
/**
 * Plugin Name: Domain-Restricted Registration
 * Description: Restricts user registration to a single email domain and requires email confirmation before login.
 * Version:     2.0.0
 * Requires at least: 5.5
 * Requires PHP: 7.4
 * Author:      George Stephanis
 * License:     GPL-2.0-or-later
 *
 * Configure the allowed domain in Settings > General under "Allowed Registration Domain".
 * When set, only email addresses from that domain may register. New registrants receive
 * a confirmation email containing a password-set link and cannot log in until they click it.
 * Leaving the field empty disables all restrictions and restores default WordPress behaviour.
 *
 * Note: Activation links expire after 24 hours (WordPress default). If a user does not
 * activate in time, a site admin can delete and re-register the account.
 *
 * @package domain-restricted-registration
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** Option key storing the single allowed email domain (e.g. "example.com"). */
const DRR_OPTION_KEY = 'drr_allowed_domain';

/** User-meta key that marks an account as pending email confirmation. */
const DRR_META_KEY = 'drr_registration_pending';

// ---------------------------------------------------------------------------
// Hook registrations
// ---------------------------------------------------------------------------

// Settings API — register option and add the field to Settings > General.
add_action( 'admin_init', 'drr_register_setting' );
add_action( 'admin_init', 'drr_add_settings_field' );

// Validate email domain during the registration flow.
add_filter( 'registration_errors', 'drr_validate_email_domain', 10, 3 );

// Intercept at priority 1 — fires BEFORE core's wp_send_new_user_notifications at priority 10.
add_action( 'register_new_user', 'drr_intercept_registration', 1 );

// Block login for accounts that haven't confirmed their email yet.
// Priority 30 fires AFTER core credential checks at priority 20.
add_filter( 'authenticate', 'drr_block_pending_login', 30, 3 );

// Block REST API access for pending accounts. Application passwords for the REST API
// bypass the authenticate filter — they go through determine_current_user instead.
// rest_authentication_errors fires after that resolves the current user.
add_filter( 'rest_authentication_errors', 'drr_block_pending_rest_request' );

// Activate the account when the user sets their password via the confirmation link.
add_action( 'after_password_reset', 'drr_activate_account', 10, 2 );

// JS — show/hide toggle and domain validation. Only outputs on the General Settings screen.
add_action( 'admin_footer-options-general.php', 'drr_admin_scripts' );

// Handle the "Enable registration" quick-action link from the inline warning.
add_action( 'admin_post_drr_enable_registration', 'drr_handle_enable_registration' );

// ---------------------------------------------------------------------------
// Section 1: Settings registration
// ---------------------------------------------------------------------------

/**
 * Registers the drr_allowed_domain option with the general settings group so
 * it is saved automatically when the General Settings form is submitted.
 */
function drr_register_setting(): void {
	register_setting(
		'general',
		DRR_OPTION_KEY,
		array(
			'type'              => 'string',
			'sanitize_callback' => 'drr_sanitize_domain',
			'default'           => '',
			'show_in_rest'      => false,
		)
	);
}

/**
 * Sanitises and validates the domain value before it is stored.
 *
 * Accepts "example.com" or "@example.com". Rejects obviously malformed input
 * and reverts to the previously stored value, adding a settings error.
 *
 * @param mixed $value Raw value submitted from the settings form.
 * @return string Sanitised domain, or the previous good value on failure.
 */
function drr_sanitize_domain( $value ): string {
	$value = strtolower( trim( sanitize_text_field( (string) $value ) ) );
	$value = ltrim( $value, '@' ); // Forgive users who type @example.com.

	if ( '' === $value ) {
		return ''; // Empty = restriction disabled; always valid.
	}

	// Deliberately liberal check — not RFC-exhaustive, just catches obvious mistakes.
	if ( ! preg_match( '/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/', $value ) ) {
		add_settings_error(
			DRR_OPTION_KEY,
			'drr_invalid_domain',
			__( 'Invalid domain format. Enter a domain like "example.com" without the @ symbol.', 'domain-restricted-registration' )
		);
		return (string) get_option( DRR_OPTION_KEY, '' );
	}

	return $value;
}

// ---------------------------------------------------------------------------
// Section 2: Settings field (UI)
// ---------------------------------------------------------------------------

/**
 * Adds the "Allowed Registration Domain" field to the default section of the
 * General settings page, rendering inside the existing Membership table via
 * do_settings_fields('general','default').
 */
function drr_add_settings_field(): void {
	add_settings_field(
		'drr_allowed_domain_field',
		__( 'Limit Registration Domain', 'domain-restricted-registration' ),
		'drr_render_domain_field',
		'general',
		'default'
	);
}

/**
 * Renders the text input for the allowed domain setting.
 */
function drr_render_domain_field(): void {
	$value = get_option( DRR_OPTION_KEY, '' );
	?>
	<div id="drr-domain-wrapper">
		<input
			type="text"
			id="<?php echo esc_attr( DRR_OPTION_KEY ); ?>"
			name="<?php echo esc_attr( DRR_OPTION_KEY ); ?>"
			value="<?php echo esc_attr( $value ); ?>"
			placeholder="example.com"
			class="regular-text"
		/>
		<span id="drr-domain-notice" style="margin-left:8px;display:none;" aria-live="polite"></span>
		<p class="description">
			<?php esc_html_e( 'If set, only email addresses from this domain may register and new accounts must confirm their email before logging in. Leave empty to allow all domains. Requires "Anyone can register" to be enabled above.', 'domain-restricted-registration' ); ?>
		</p>
		<div id="drr-registration-warning" class="notice notice-warning inline" style="display:none;" aria-live="polite">
			<p>
			<?php
			$allowed_tags = array(
				'strong' => array(),
				'a'      => array( 'href' => array() ),
			);
			/* translators: %s: "Enable registration" link URL */
			$warning_template = __( '<strong>Warning:</strong> "Anyone can register" is currently disabled, so this domain restriction has no effect. <a href="%s">Enable registration</a>.', 'domain-restricted-registration' );
			printf(
				wp_kses( $warning_template, $allowed_tags ),
				esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=drr_enable_registration' ), 'drr_enable_registration' ) )
			);
			?>
			</p>
		</div>
	</div>
	<?php
}

// ---------------------------------------------------------------------------
// Section 3: Admin scripts (show/hide toggle + domain DNS validation)
// ---------------------------------------------------------------------------

/**
 * Outputs inline scripts for the General Settings page.
 *
 * Relocation: moves the domain field row into the DOM immediately after the
 * "New User Default Role" row so it sits visually inside the Membership block.
 * (Settings API fields render at the bottom of the page via
 * do_settings_fields('general','default') at options-general.php:571, far from
 * the hardcoded Membership section rows.)
 *
 * DNS validation: on focusout of the domain input, queries the Google
 * DNS-over-HTTPS JSON API to confirm the domain exists. Displays a notice
 * beneath the input — a warning on NXDOMAIN, a checkmark on success.
 * Network errors are silently ignored so a connectivity hiccup never
 * blocks the admin from saving.
 */
function drr_admin_scripts(): void {
	?>
	<script>
	( function () {

		/* ── Relocate the row next to the Membership section ── */
		var wrapper  = document.getElementById( 'drr-domain-wrapper' );
		var anchor   = document.getElementById( 'default_role' ); // "New User Default Role" select.

		if ( wrapper && anchor ) {
			var ourRow    = wrapper.closest( 'tr' );
			var anchorRow = anchor.closest( 'tr' );
			if ( ourRow && anchorRow && anchorRow.parentNode ) {
				anchorRow.insertAdjacentElement( 'afterend', ourRow );
			}
		}

		/* ── Inline misconfiguration warning ── */
		var regCheckbox = document.getElementById( 'users_can_register' );
		var warning     = document.getElementById( 'drr-registration-warning' );

		if ( regCheckbox && warning ) {
			function updateWarning() {
				var hasDomain = input && '' !== input.value.trim();
				warning.style.display = ( hasDomain && ! regCheckbox.checked ) ? '' : 'none';
			}

			regCheckbox.addEventListener( 'change', updateWarning );
			updateWarning(); // Reflect current state on page load.
		}

		/* ── DNS-over-HTTPS domain validation ── */
		var input  = document.getElementById( '<?php echo esc_js( DRR_OPTION_KEY ); ?>' );
		var notice = document.getElementById( 'drr-domain-notice' );

		if ( ! input || ! notice ) {
			return;
		}

		// Also re-evaluate the warning whenever the domain value changes.
		if ( warning ) {
			input.addEventListener( 'input', updateWarning );
		}

		var lastChecked = '';

		input.addEventListener( 'focusout', function () {
			var domain = this.value.trim().toLowerCase().replace( /^@/, '' );

			// Nothing entered, or the same domain we already validated — clear and return.
			if ( '' === domain ) {
				notice.style.display = 'none';
				notice.textContent   = '';
				lastChecked          = '';
				return;
			}
			if ( domain === lastChecked ) {
				return;
			}
			lastChecked = domain;

			// Show a neutral "checking…" state while the request is in flight.
			notice.style.display = '';
			notice.style.color   = '';
			notice.textContent   = '<?php echo esc_js( __( 'Checking domain…', 'domain-restricted-registration' ) ); ?>';

			fetch(
				'https://dns.google/resolve?name=' + encodeURIComponent( domain ) + '&type=A',
				{ headers: { 'Accept': 'application/dns-json' } }
			)
			.then( function ( response ) {
				if ( ! response.ok ) {
					throw new Error( 'HTTP ' + response.status );
				}
				return response.json();
			} )
			.then( function ( data ) {
				if ( 3 === data.Status ) {
					// NXDOMAIN — the domain does not exist in DNS.
					notice.style.color = '#d63638'; // WP admin error red.
					notice.textContent = '<?php echo esc_js( __( '⚠ Domain not found in DNS. Double-check the spelling.', 'domain-restricted-registration' ) ); ?>';
				} else {
					// Any other status (including NOERROR with no A records) means the domain resolves.
					notice.style.color = '#00a32a'; // WP admin success green.
					notice.textContent = '<?php echo esc_js( __( '✓ Domain found.', 'domain-restricted-registration' ) ); ?>';
				}
			} )
			.catch( function () {
				// Network error or unexpected response — don't alarm the admin.
				notice.style.display = 'none';
				notice.textContent   = '';
			} );
		} );

	}() );
	</script>
	<?php
}

// ---------------------------------------------------------------------------
// Section 4: Registration validation
// ---------------------------------------------------------------------------

/**
 * Validates that the submitted email address matches the configured domain.
 *
 * Hooked to 'registration_errors' (wp-includes/user.php:3565).
 *
 * @param WP_Error $errors               Existing registration errors.
 * @param string   $sanitized_user_login Sanitised username.
 * @param string   $user_email           Submitted email address.
 * @return WP_Error Original or augmented error object.
 */
function drr_validate_email_domain( WP_Error $errors, string $sanitized_user_login, string $user_email ): WP_Error {
	$allowed_domain = get_option( DRR_OPTION_KEY, '' );
	if ( '' === $allowed_domain ) {
		return $errors; // No restriction configured.
	}

	// If the email is already invalid/empty, let core report that; don't pile on.
	if ( ! is_email( $user_email ) ) {
		return $errors;
	}

	$submitted_domain = strtolower( substr( $user_email, strrpos( $user_email, '@' ) + 1 ) );

	if ( $submitted_domain !== $allowed_domain ) {
		$errors->add(
			'drr_domain_mismatch',
			sprintf(
				/* translators: %s: the required email domain */
				__( '<strong>Error:</strong> Registration is only open to <strong>@%s</strong> email addresses.', 'domain-restricted-registration' ),
				esc_html( $allowed_domain )
			)
		);
	}

	return $errors;
}

// ---------------------------------------------------------------------------
// Section 5: Registration interception
// ---------------------------------------------------------------------------

/**
 * Fires at priority 1 on 'register_new_user', before core's
 * wp_send_new_user_notifications at priority 10.
 *
 * When domain restriction is active:
 *   1. Removes core's default notification so ours is the only email sent.
 *   2. Marks the account as pending email confirmation via user meta.
 *   3. Sends the admin a standard new-user notification.
 *   4. Sends the registrant a custom "Confirm your email" message.
 *
 * @param int $user_id Newly created user ID.
 */
function drr_intercept_registration( int $user_id ): void {
	if ( '' === get_option( DRR_OPTION_KEY, '' ) ) {
		return; // No restriction active — leave default behaviour intact.
	}

	// Prevent core's default notification (would send a second email to the user).
	remove_action( 'register_new_user', 'wp_send_new_user_notifications' );

	// Flag the account as unconfirmed.
	update_user_meta( $user_id, DRR_META_KEY, '1' );

	// Still notify the site admin of the new registration.
	wp_new_user_notification( $user_id, null, 'admin' );

	// Send the registrant their confirmation email.
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
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- intentional server-side diagnostic; no suitable WP alternative for plugin error logging.
		error_log(
			sprintf(
				'DRR: Could not generate activation key for user %d (%s): %s',
				$user_id,
				$user->user_email,
				$key->get_error_message()
			)
		);
		return;
	}

	/*
	 * Build the activation URL in the same format as core (pluggable.php:2382).
	 * login= comes before key= to avoid trailing-period issues in some email
	 * clients (see WordPress Trac #42957).
	 */
	$activation_url = network_site_url(
		'wp-login.php?action=rp&login=' . rawurlencode( $user->user_login ) . '&key=' . $key,
		'login'
	);

	$blogname = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );

	// Respect the user's preferred locale if set (matches core's approach in pluggable.php).
	$switched_locale = switch_to_user_locale( $user_id );

	/* translators: %s: site name */
	$subject = sprintf( __( '[%s] Confirm your email address', 'domain-restricted-registration' ), $blogname );

	/* translators: %s: user's display name */
	$message = sprintf( __( 'Hi %s,', 'domain-restricted-registration' ), $user->display_name ) . "\r\n\r\n";
	/* translators: %s: site name */
	$message .= sprintf( __( 'Thank you for registering on %s.', 'domain-restricted-registration' ), $blogname ) . "\r\n\r\n";
	$message .= __( 'To activate your account and set your password, visit the link below. This link expires in 24 hours.', 'domain-restricted-registration' ) . "\r\n\r\n";
	$message .= $activation_url . "\r\n\r\n";
	$message .= __( 'If you did not register for this site, you can safely ignore this email.', 'domain-restricted-registration' ) . "\r\n";

	wp_mail( $user->user_email, $subject, $message );

	if ( $switched_locale ) {
		restore_previous_locale();
	}
}

// ---------------------------------------------------------------------------
// Section 6: Block login for unconfirmed accounts
// ---------------------------------------------------------------------------

/**
 * Returns a WP_Error for any user whose account has not yet been confirmed.
 *
 * Hooked to 'authenticate' at priority 30, after core's credential checks at
 * priority 20. Returning WP_Error aborts authentication and triggers wp_login_failed.
 *
 * @param WP_User|WP_Error|null $user     Result from earlier authenticate handlers.
 * @param string                $username Submitted username.
 * @param string                $password Submitted password.
 * @return WP_User|WP_Error|null Unchanged $user, or a WP_Error if account is pending.
 */
function drr_block_pending_login( $user, string $username, string $password ) {
	if ( is_wp_error( $user ) || null === $user ) {
		return $user;
	}

	if ( ! get_user_meta( $user->ID, DRR_META_KEY, true ) ) {
		return $user;
	}

	return new WP_Error(
		'drr_account_pending',
		sprintf(
			/* translators: %s: the user's email address */
			__( '<strong>Error:</strong> Your account is not yet active. Please check your inbox at <strong>%s</strong> for the confirmation link.', 'domain-restricted-registration' ),
			esc_html( $user->user_email )
		)
	);
}

/**
 * Blocks REST API access for accounts that have not yet confirmed their email.
 *
 * Application passwords authenticate via the determine_current_user filter,
 * bypassing the authenticate filter entirely. rest_authentication_errors fires
 * after determine_current_user resolves the user, making it the correct second
 * interception point.
 *
 * @param WP_Error|true|null $result Existing authentication result.
 * @return WP_Error|true|null Unchanged, or a WP_Error with HTTP 401 status.
 */
function drr_block_pending_rest_request( $result ) {
	if ( ! empty( $result ) ) {
		return $result;
	}

	$user = wp_get_current_user();
	if ( $user->exists() && get_user_meta( $user->ID, DRR_META_KEY, true ) ) {
		return new WP_Error(
			'drr_account_pending',
			__( 'Your account is not yet active. Please confirm your email address before using the API.', 'domain-restricted-registration' ),
			array( 'status' => 401 )
		);
	}

	return $result;
}

// ---------------------------------------------------------------------------
// Section 7: Account activation on password set
// ---------------------------------------------------------------------------

/**
 * Activates a pending account once the user sets their password via the
 * confirmation link. Fires for all password resets, so we check the meta flag.
 *
 * @param WP_User $user     The user whose password was reset.
 * @param string  $new_pass The newly set password (unused).
 */
function drr_activate_account( WP_User $user, string $new_pass ): void {
	if ( ! get_user_meta( $user->ID, DRR_META_KEY, true ) ) {
		return;
	}

	delete_user_meta( $user->ID, DRR_META_KEY );

	// Clean up the "default password nag" core sets on registration.
	delete_user_meta( $user->ID, 'default_password_nag' );
}

// ---------------------------------------------------------------------------
// Section 8: Enable-registration action handler
// ---------------------------------------------------------------------------

/**
 * Handles the "Enable registration" action link from the inline warning.
 *
 * Verifies the nonce and capability, sets users_can_register to 1, then
 * redirects back to Settings > General.
 */
function drr_handle_enable_registration(): void {
	check_admin_referer( 'drr_enable_registration' );

	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'Sorry, you are not allowed to do that.', 'domain-restricted-registration' ) );
	}

	update_option( 'users_can_register', 1 );

	wp_safe_redirect( admin_url( 'options-general.php' ) );
	exit;
}
