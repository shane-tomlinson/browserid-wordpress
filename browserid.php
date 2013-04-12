<?php
/*
Plugin Name: Mozilla Persona
Plugin URI: http://wordpress.org/extend/plugins/browserid/
Plugin Repo: https://github.com/shane-tomlinson/browserid-wordpress
Description: Mozilla Persona, the safest & easiest way to sign in
Version: 0.37
Author: Shane Tomlinson
Author URI: https://shanetomlinson.com
Original Author: Marcel Bokhorst
Original Author URI: http://blog.bokhorst.biz/about/
*/

/*
	Copyright (c) 2011, 2012, 2013 Marcel Bokhorst

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#error_reporting(E_ALL);

// Check PHP version
if (version_compare(PHP_VERSION, '5.0.0', '<'))
	die('Mozilla Persona requires at least PHP 5, installed version is ' . PHP_VERSION);

// Define constants
define('c_bid_text_domain', 'browserid');
define('c_bid_option_version', 'bid_version');
define('c_bid_option_request', 'bid_request');
define('c_bid_option_response', 'bid_response');
define('c_bid_browserid_login_cookie', 'bid_browserid_login_' . COOKIEHASH);

// Define class
if (!class_exists('M66BrowserID')) {
	class M66BrowserID {
		// Class variables
		var $debug = null;

		// Constructor
		function __construct() {
			// Get plugin options
			$options = get_option('browserid_options');

			// Debug mode
			$this->debug = (isset($options['browserid_debug']) && $options['browserid_debug']);

			// Register de-activation
			register_deactivation_hook(__FILE__, array(&$this, 'Deactivate'));

			// Register actions & filters
			add_action('init', array(&$this, 'Init'), 0);
			add_action('set_auth_cookie', array(&$this, 'Set_auth_cookie'));
			add_action('clear_auth_cookie', array(&$this, 'Clear_auth_cookie'));
			add_filter('wp_authenticate_user', array(&$this, 'Check_username_password_auth_allowed_allowed'));
			add_filter('login_message', array(&$this, 'Login_message'));
			add_action('login_form', array(&$this, 'Login_form'));

			add_action('register_form', array(&$this, 'Register_form'));
			add_action('user_register', array(&$this, 'Register_user_register_action'));
			add_filter('registration_redirect', array(&$this, 'Register_redirect_filter'));

			add_action('widgets_init', create_function('', 'return register_widget("BrowserID_Widget");'));
			if (is_admin()) {
				add_action('admin_menu', array(&$this, 'Admin_menu'));
				add_action('admin_init', array(&$this, 'Admin_init'));
			}
			add_action('http_api_curl', array(&$this, 'http_api_curl'));
                        add_action('admin_bar_menu', array(&$this, 'Admin_toolbar'), 999);

			// Comment integration
			if (isset($options['browserid_comments']) && $options['browserid_comments']) {
				add_filter('comment_form_default_fields', array(&$this, 'Comment_form_fields'));
				add_action('comment_form', array(&$this, 'Comment_form'));
			}

			// bbPress integration
			if (isset($options['browserid_bbpress']) && $options['browserid_bbpress']) {
				add_action('bbp_allow_anonymous', create_function('', 'return !is_user_logged_in();'));
				add_action('bbp_is_anonymous', create_function('', 'return !is_user_logged_in();'));
				add_action('bbp_theme_before_topic_form_submit_button', array(&$this, 'bbPress_submit'));
				add_action('bbp_theme_before_reply_form_submit_button', array(&$this, 'bbPress_submit'));
			}

			// Shortcode
			add_shortcode('browserid_loginout', array(&$this, 'Shortcode_loginout'));
			add_shortcode('mozilla_persona', array(&$this, 'Shortcode_loginout'));
		}

		// Handle plugin activation
		function Activate() {
			global $wpdb;
			$version = get_option(c_bid_option_version);
			if ($version < 2) {
				$options = get_option('browserid_options');
				$options['browserid_logout_html'] = __('Logout', c_bid_text_domain);
				update_option('browserid_options', $options);
			}
			update_option(c_bid_option_version, 2);
		}

		// Handle plugin deactivation
		function Deactivate() {
			// TODO: delete options
		}

		// Initialization
		function Init() {
			global $user_email;
			get_currentuserinfo();

			// I18n
			load_plugin_textdomain(c_bid_text_domain, false, dirname(plugin_basename(__FILE__)));

			// Check for assertion
			self::Check_assertion();

			// Enqueue BrowserID scripts
			wp_register_script('browserid', 'https://login.persona.org/include.js', array(), '', true);
			// This one script takes care of all work.
			wp_register_script('browserid_common', plugins_url('login.js', __FILE__), array('jquery', 'browserid'), '', true);

			$redirect = (isset($_REQUEST['redirect_to']) ? $_REQUEST['redirect_to'] : null);
			$browserid_error = (isset($_REQUEST['browserid_error']) ? $_REQUEST['browserid_error'] : null);
			$browserid_failed = __('Verification failed', c_bid_text_domain);
			$data_array = array(
				'siteurl' => get_site_url(null, '/'),
				'login_redirect' => $redirect,
				'error' => $browserid_error,
				'failed' => $browserid_failed,
				'sitename' => self::Get_sitename(),
				'sitelogo' => self::Get_sitelogo(),
				'logout_redirect' => wp_logout_url(),
				'logged_in_user' => self::Get_browserid_loggedin_user()
			);
			wp_localize_script( 'browserid_common', 'browserid_common', $data_array );
			wp_enqueue_script('browserid_common');
		}

		// Get the currently logged in user, iff they authenticated using BrowserID
		function Get_browserid_loggedin_user() {
		  global $user_email;
		  get_currentuserinfo();

		  if ( isset( $_COOKIE[c_bid_browserid_login_cookie] ) ) {
			return $user_email;
		  }

		  return null;
		}

		function Check_assertion() {
			// Workaround for Microsoft IIS bug
			if (isset($_REQUEST['?browserid_assertion']))
				$_REQUEST['browserid_assertion'] = $_REQUEST['?browserid_assertion'];

			// Verify received assertion
			if (isset($_REQUEST['browserid_assertion'])) {
				// Get options
				$options = get_option('browserid_options');

				// Get assertion/audience/remember me
				$assertion = $_REQUEST['browserid_assertion'];
				$audience = $_SERVER['HTTP_HOST'];

				$rememberme = (isset($_REQUEST['rememberme']) && $_REQUEST['rememberme'] == 'true');

				// Get verification server URL
				if (isset($options['browserid_vserver']) && $options['browserid_vserver'])
					$vserver = $options['browserid_vserver'];
				else
					$vserver = 'https://verifier.login.persona.org/verify';

				// No SSL verify?
				$noverify = (isset($options['browserid_noverify']) && $options['browserid_noverify']);

				// Build arguments
				$args = array(
					'method' => 'POST',
					'timeout' => 30,
					'redirection' => 0,
					'httpversion' => '1.0',
					'blocking' => true,
					'headers' => array(),
					'body' => array(
						'assertion' => $assertion,
						'audience' => $audience
					),
					'cookies' => array(),
					'sslverify' => !$noverify
				);
				if ($this->debug)
					update_option(c_bid_option_request, $vserver . ' ' . print_r($args, true));

				// Verify assertion
				$response = wp_remote_post($vserver, $args);

				// Check result
				if (is_wp_error($response)) {
					// Debug info
					$message = __($response->get_error_message());
					if ($this->debug) {
						update_option(c_bid_option_response, $response);
						header('Content-type: text/plain');
						echo $message . PHP_EOL;
						print_r($response);
						exit();
					}
					else
						self::Handle_error($message);
				}
				else {
					// Persist debug info
					if ($this->debug) {
						$response['vserver'] = $vserver;
						$response['audience'] = $audience;
						$response['rememberme'] = $rememberme;
						update_option(c_bid_option_response, $response);
					}

					// Decode response
					$result = json_decode($response['body'], true);

					// Check result
					if (empty($result) || empty($result['status'])) {
						// No result or status
						$message = __('Verification void', c_bid_text_domain);
						if ($this->debug) {
							header('Content-type: text/plain');
							echo $message . PHP_EOL;
							echo $response['response']['message'] . PHP_EOL;
							print_r($response);
							exit();
						}
						else
							self::Handle_error($message);
					}
					else if ($result['status'] == 'okay' &&
							$result['audience'] == $audience) {
						// Check expiry time
						$novalid = (isset($options['browserid_novalid']) && $options['browserid_novalid']);
						if ($novalid || time() < $result['expires'] / 1000)
						{
							// Succeeded
							if (self::Is_comment())
								self::Handle_comment($result);
							else if (self::Is_registration())
								self::Handle_registration($result);
							else
								self::Handle_login($result, $rememberme);
						}
						else {
							$message = __('Verification invalid', c_bid_text_domain);
							if ($this->debug) {
								header('Content-type: text/plain');
								echo $message . PHP_EOL;
								echo 'time=' . time() . PHP_EOL;
								print_r($result);
								exit();
							}
							else
								self::Handle_error($message);
						}
					}
					else {
						// Failed
						$message = __('Verification failed', c_bid_text_domain);
						if (isset($result['reason']))
							$message .= ': ' . __($result['reason'], c_bid_text_domain);
						if ($this->debug) {
							header('Content-type: text/plain');
							echo $message . PHP_EOL;
							echo 'audience=' . $audience . PHP_EOL;
							echo 'vserver=' . parse_url($vserver, PHP_URL_HOST) . PHP_EOL;
							echo 'time=' . time() . PHP_EOL;
							print_r($result);
							exit();
						}
						else
							self::Handle_error($message);
					}
				}
			}
		}

		// Determine if login or comment
		function Is_comment() {
			$options = get_option('browserid_options');
			if ((isset($options['browserid_comments']) && $options['browserid_comments']) ||
				(isset($options['browserid_bbpress']) && $options['browserid_bbpress']))
				return (isset($_REQUEST['browserid_comment']) ? $_REQUEST['browserid_comment'] : null);
			else
				return null;
		}

		function Is_registration() {
			$action = isset($_REQUEST['action']) ? $_REQUEST['action'] : null;
			return $action == 'register';
		}

		// Generic error handling
		function Handle_error($message) {
			$post_id = self::Is_comment();
			$redirect = isset($_REQUEST['redirect_to']) ? $_REQUEST['redirect_to'] : null;
			$url = ($post_id ? get_permalink($post_id) : wp_login_url($redirect));
			$url .= (strpos($url, '?') === false ? '?' : '&') . 'browserid_error=' . urlencode($message);
			if ($post_id)
				$url .= '#browserid_' . $post_id;
			wp_redirect($url);
			exit();
		}

		// Process login
		function Handle_login($result, $rememberme) {
			$options = get_option('browserid_options');
			// Login
			$user = self::Login_by_email($result['email'], $rememberme);
			if ($user) {
				// Beam me up, Scotty!
				if (isset($result['redirect_to'])) 
					$redirect_to = $result['redirect_to'];
				else if (isset($options['browserid_login_redir']) && $options['browserid_login_redir'])
					$redirect_to = $options['browserid_login_redir'];
				else if (isset($_REQUEST['redirect_to']))
					$redirect_to = $_REQUEST['redirect_to'];
				else
					$redirect_to = admin_url();
				$redirect_to = apply_filters('login_redirect', $redirect_to, '', $user);
				wp_redirect($redirect_to);
				exit();
			}
			else {
				// User not found? If auto-registration is 
				// enabled, try to create a new user with the 
				// email address as the username.
				if ( !get_option('users_can_register') ) {
					$message = __('You must already have an account to log in with Persona.');
					self::Handle_error($message);
					exit();
				} else if( !isset($options['browserid_auto_create_new_users']) || !$options['browserid_auto_create_new_users']) {
					$message = __('You must already have an account to log in with Persona.');

					self::Handle_error($message);
					exit();
				} else {
					$user_id = wp_create_user($result['email'], 'password', $result['email']);
					
					if ($user_id) {
						if (isset($options['browserid_newuser_redir']) && $options['browserid_newuser_redir']) {
							$result['redirect_to'] = $options['browserid_newuser_redir'];
						} else {
							$result['redirect_to'] = admin_url() . 'profile.php';
						}
						self::Handle_login($result, $rememberme);
					} else {				
						$message = __('New user creation failed', c_bid_text_domain);
						$message .= ' (' . $result['email'] . ')';
						if ($this->debug) {
							header('Content-type: text/plain');
							echo $message . PHP_EOL;
							print_r($result);
						}
						else 
							self::Handle_error($message);

						exit();
					}
				}
			}
		}

		// Login user using e-mail address
		function Login_by_email($email, $rememberme) {
			$userdata = get_user_by('email', $email);
			return self::Login_by_userdata($userdata, $rememberme);
		}

		function Login_by_id($user_id) {
			$userdata = get_user_by('id', $user_id);
			return self::Login_by_userdata($userdata, true);
		}

		function Login_by_userdata($userdata, $rememberme) {
			global $user;
			$user = null;

			if ($userdata) {
				$user = new WP_User($userdata->ID);
				$this->browserid_login = true;
				wp_set_current_user($userdata->ID, $userdata->user_login);
				wp_set_auth_cookie($userdata->ID, $rememberme);
				do_action('wp_login', $userdata->user_login);
			}
			return $user;
		}

		// Process comment
		function Handle_comment($result) {
			// Initialize
			$email = $result['email'];
			$author = $_REQUEST['author'];
			$url = $_REQUEST['url'];

			// Check WordPress user
			$userdata = get_user_by('email', $email);
			if ($userdata) {
				$author = $userdata->display_name;
				$url = $userdata->user_url;
			}
			else if (empty($author) || empty($url)) {
				// Check Gravatar profile
				$response = wp_remote_get('http://www.gravatar.com/' . md5($email) . '.json');
				if (!is_wp_error($response)) {
					$json = json_decode($response['body']);
					if (empty($author)) 
						$author = $json->entry[0]->displayName;

					if (empty($url)) 
						$url = $json->entry[0]->profileUrl;
				}
			}

			if (empty($author)) {
				// Use first part of e-mail
				$parts = explode('@', $email);
				$author = $parts[0];
			}


			// Update post variables
			$_POST['author'] = $author;
			$_POST['email'] = $email;
			$_POST['url'] = $url;
			// bbPress
			$_POST['bbp_anonymous_name'] = $author;
			$_POST['bbp_anonymous_email'] = $email;
			$_POST['bbp_anonymous_website'] = $url;
		}

		// Set a cookie that keeps track whether the user signed in using BrowserID
		function Set_auth_cookie($auth_cookie, $expire, $expiration, $user_id, $scheme) {
			// Persona should only manage Persona logins. If this is a BrowserID login, 
			// keep track of it so that the user is not automatically logged out if 
			// they log in via other means.
			if ($this->browserid_login) {
				$secure = $scheme == "secure_auth";
				setcookie(c_bid_browserid_login_cookie, 1, $expire, COOKIEPATH, COOKIE_DOMAIN, $secure, true);
			}
			else {
				// If the user is not logged in via BrowserID, clear the cookie.
				self::Clear_auth_cookie();
			}
		}

		// Clear the cookie that keeps track of whether hte user signed in using BrowserID
		function Clear_auth_cookie() {
			$expire = time() - YEAR_IN_SECONDS;
			setcookie(c_bid_browserid_login_cookie, ' ', $expire, COOKIEPATH, COOKIE_DOMAIN);
		}

		// Check whether normal username/password authentication is allowed
		function Check_username_password_auth_allowed_allowed($user, $password) {
			if (self::Is_browserid_only_auth()) {
				return new WP_error('invalid_login', 'Only BrowserID logins are allowed');
			}

			return $user;
		}

		// Filter login error message
		function Login_message($message) {
			if (isset($_REQUEST['browserid_error']))
				$message .= '<div id="login_error"><strong>' . htmlentities(stripslashes($_REQUEST['browserid_error'])) . '</strong></div>';
			return $message;
		}

		// Add login button to login page
		function Login_form() {
			echo '<p>' . self::Get_loginout_html(false) . '<br /><br /></p>';
		}

		// Does the site have browserid only authentication enabled.
		function Is_browserid_only_auth() {
			$options = get_option('browserid_options');

			return ((isset($options['browserid_only_auth']) && 
						$options['browserid_only_auth']));
		}

		// Add Persona button to registration form and remove the email form.
		function Register_form() {
			// Only enable registration via Persona if Persona is the only 
			// authentication mechanism or else the user will not see the
			// "check your email" screen.
			if (self::Is_browserid_only_auth()) {
				echo '<input type="hidden" name="browserid_assertion" id="browserid_assertion" />';

				// XXX collapse the link stuff into Get_login_html
				$html = '<img src="' . self::Get_image_url() . '" style="border: none; vertical-align: middle; margin-right: 5px;" />';
				echo '<a href="#" onclick="return browserid_register();" title="Mozilla Persona" class="browserid">' . $html  . '</a>';

				echo 
				'<style>#user_email,[for=user_email],#reg_passmail{display:none;}';
				echo '#wp-submit { position: absolute; left: -9999px !important; }</style>';
			}
		}

		// Process registration - get the email address from the assertion and 
		// process the rest of the form.
		function Handle_registration($result) {
			if (self::Is_browserid_only_auth()) {
				$_POST['user_email'] = $result['email'];
			}
		}


		// Now that the user is registered, log them in
		function Register_user_register_action($user_id) {
			if (self::Is_browserid_only_auth()) {
				self::Login_by_id($user_id);
			}
		}

		function Register_redirect_filter($redirect_to) {
			if ($redirect_to) return $redirect_to;

			if (self::Is_browserid_only_auth()) {
				// The user successfully signed up using Persona, 
				// send them to their profile page
				return admin_url() . 'profile.php';
			}

			return '';
		}


		// bbPress integration
		function bbPress_submit() {
			$id = bbp_get_topic_id();
			if (empty($id))
				$id = bbp_get_forum_id();
			self::Comment_form($id);
		}

		// Imply anonymous commenting
		function bbPress_anonymous() {
			return !is_user_logged_in();
		}

		// Get rid of the email field in the comment form
		function Comment_form_fields($fields) {
			$options = get_option('browserid_options');
			if ((isset($options['browserid_comments']) && $options['browserid_comments'])) {
				unset($fields['email']);
			}
			return $fields;
		}

		// Add BrowserID to comment form
		function Comment_form($post_id) {
			if (!is_user_logged_in()) {
				// Get link content
				$options = get_option('browserid_options');
				if (empty($options['browserid_comment_html']))
					$html = '<img src="' . self::Get_image_url() . '" style="border: none; vertical-align: middle; margin-right: 5px;" />';
				else
					$html = $options['browserid_comment_html'];

				// Render link
				echo '<a href="#" id="browserid_' . $post_id . '" onclick="return browserid_comment(' . $post_id . ');" title="Mozilla Persona" class="browserid">' . $html . '</a>';
				echo self::What_is();
				// If it is a Persona login, hide the submit button.
				echo '<style>#respond input[type=submit] { position: absolute; left: -9999px !important; }</style>';

				// Display error message
				if (isset($_REQUEST['browserid_error'])) {
					echo '<span style="color: red; font-weight: bold; margin: 10px; vertical-align: top;">';
					echo htmlspecialchars(stripslashes($_REQUEST['browserid_error']), ENT_QUOTES, get_bloginfo('charset'));
					echo '</span>';
				}
			}
		}

		// Shortcode "mozilla_persona"
		function Shortcode_loginout() {
			return self::Get_loginout_html();
		}

		// Git spiffy logout text for Persona
		function Get_logout_text() {
			// User logged in
			if (empty($options['browserid_logout_html']))
				$html = __('Logout');
			else
				$html = $options['browserid_logout_html'];

			return $html;
		}


		// Build HTML for login/out button/link
		function Get_loginout_html($check_login = true) {
			$options = get_option('browserid_options');

			if ($check_login && is_user_logged_in()) {
				$html = self::Get_logout_text();

				// Simple link
				if (empty($html))
					return '';
				else
					return '<a href="' . wp_logout_url() . '">' . $html . '</a>';
			}
			else {
				// User not logged in
				if (empty($options['browserid_login_html']))
					$html = '<img src="' . self::Get_image_url() . '" style="border: 0;" />';
				else
					$html = $options['browserid_login_html'];
				// Button
				$html = '<a href="#" onclick="return browserid_login();"  title="Mozilla Persona" class="browserid">' . $html . '</a>';
				$html .= '<br />' . self::What_is();

				// Hide the login form. While this does not truely prevent users from 
				// from logging in using the standard authentication mechanism, it 
				// cleans up the login form a bit.
				if (self::Is_browserid_only_auth()) {
					$html .= '<style>#user_login, [for=user_login], #user_pass, [for=user_pass], [name=log], [name=pwd] { display: none; }</style>'; 
				}

				return $html;
			}
		}

		// Get localized image URL
		function Get_image_url() {
			$image_url = plugins_url('browserid-en_US.png', __FILE__);
			$locale = get_bloginfo('language');
			$locale = str_replace('-', '_', $locale);
			if (!empty($locale)) {
				$image = 'browserid-' . $locale . '.png';
				$image_file = dirname(__FILE__) . '/' . $image;
				if (file_exists($image_file))
					$image_url = plugins_url($image, __FILE__);
			}
			return $image_url;
		}

		function What_is() {
			return '<a href="https://login.persona.org/" target="_blank" style="font-size: smaller;">' . __('What is Persona?', c_bid_text_domain) . '</a>';
		}

		// Get (customized) site name
		function Get_sitename() {
			$name = null;
			$options = get_option('browserid_options');
			if (isset($options['browserid_sitename']))
				$name = $options['browserid_sitename'];
			if (empty($name))
				$name = get_bloginfo('name');
			return $name;
		}

		// Get site logo
		function Get_sitelogo() {
			$options = get_option('browserid_options');
			// sitelogo is only valid with SSL connections
			if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443)
				if (isset($options['browserid_sitelogo']))
					return $options['browserid_sitelogo'];
			return '';
		}

		// Override logout on site menu
		function Admin_toolbar($wp_toolbar) {
			$logged_in_user = self::Get_browserid_loggedin_user();

			// If the user is signed in via Persona, replace their toolbar logout 
			// with a logout that will work with Persona.
			if ( $logged_in_user ) {
				$wp_toolbar->remove_node('logout');
				$wp_toolbar->add_node(array(
					'id' => 'logout',
					'title' => self::Get_logout_text(),
					'parent' => 'user-actions',
					'href' => '#',
					'meta' => array(
						'onclick' => 'return browserid_logout()'
					)
				));
			}
		}


		// Register options page
		function Admin_menu() {
			if (function_exists('add_options_page'))
				add_options_page(
					__('Mozilla Persona', c_bid_text_domain) . ' ' . __('Administration', c_bid_text_domain),
					__('Mozilla Persona', c_bid_text_domain),
					'manage_options',
					__FILE__,
					array(&$this, 'Administration'));
		}

		// Define options page
		function Admin_init() {
			register_setting('browserid_options', 'browserid_options', null);
			add_settings_section('plugin_main', null, array(&$this, 'Options_main'), 'browserid');
			add_settings_field('browserid_sitename', __('Site name:', c_bid_text_domain), array(&$this, 'Option_sitename'), 'browserid', 'plugin_main');
			add_settings_field('browserid_sitelogo', __('Site logo:', c_bid_text_domain), array(&$this, 'Option_sitelogo'), 'browserid', 'plugin_main');
			add_settings_field('browserid_only_auth', __('Disable non-Persona logins:', c_bid_text_domain), array(&$this, 'Option_browserid_only_auth'), 'browserid', 'plugin_main');
			add_settings_field('browserid_login_html', __('Custom login HTML:', c_bid_text_domain), array(&$this, 'Option_login_html'), 'browserid', 'plugin_main');
			add_settings_field('browserid_logout_html', __('Custom logout HTML:', c_bid_text_domain), array(&$this, 'Option_logout_html'), 'browserid', 'plugin_main');
			add_settings_field('browserid_auto_create_new_users', __('Automatically create new users with the email address as the username', c_bid_text_domain), array(&$this, 'Option_auto_create_new_users'), 'browserid', 'plugin_main');
			add_settings_field('browserid_newuser_redir', __('New user redirection URL:', c_bid_text_domain), array(&$this, 'Option_newuser_redir'), 'browserid', 'plugin_main');

			add_settings_field('browserid_login_redir', __('Login redirection URL:', c_bid_text_domain), array(&$this, 'Option_login_redir'), 'browserid', 'plugin_main');
			add_settings_field('browserid_comments', __('Enable for comments:', c_bid_text_domain), array(&$this, 'Option_comments'), 'browserid', 'plugin_main');
			add_settings_field('browserid_bbpress', __('Enable bbPress integration:', c_bid_text_domain), array(&$this, 'Option_bbpress'), 'browserid', 'plugin_main');
			add_settings_field('browserid_comment_html', __('Custom comment HTML:', c_bid_text_domain), array(&$this, 'Option_comment_html'), 'browserid', 'plugin_main');
			add_settings_field('browserid_vserver', __('Verification server:', c_bid_text_domain), array(&$this, 'Option_vserver'), 'browserid', 'plugin_main');
			add_settings_field('browserid_novalid', __('Do not check valid until time:', c_bid_text_domain), array(&$this, 'Option_novalid'), 'browserid', 'plugin_main');
			add_settings_field('browserid_noverify', __('Do not verify SSL certificate:', c_bid_text_domain), array(&$this, 'Option_noverify'), 'browserid', 'plugin_main');
			add_settings_field('browserid_debug', __('Debug mode:', c_bid_text_domain), array(&$this, 'Option_debug'), 'browserid', 'plugin_main');
		}

		// Main options section
		function Options_main() {
			// Empty
		}

		// Site name option
		function Option_sitename() {
			$options = get_option('browserid_options');
			if (empty($options['browserid_sitename']))
				$options['browserid_sitename'] = null;
			echo "<input id='browserid_sitename' name='browserid_options[browserid_sitename]' type='text' size='100' value='{$options['browserid_sitename']}' />";
			echo '<br />' . __('Default the WordPress site name', c_bid_text_domain);
		}

		// Site logo option
		function Option_sitelogo() {
			$options = get_option('browserid_options');
			if (empty($options['browserid_sitelogo']))
				$options['browserid_sitelogo'] = null;
			echo "<input id='browserid_sitelogo' name='browserid_options[browserid_sitelogo]' type='text' size='100' value='{$options['browserid_sitelogo']}' />";
			echo '<br />' . __('Absolute path, works only with SSL', c_bid_text_domain);
		}

		// Login HTML option
		function Option_login_html() {
			$options = get_option('browserid_options');
			if (empty($options['browserid_login_html']))
				$options['browserid_login_html'] = null;
			echo "<input id='browserid_login_html' name='browserid_options[browserid_login_html]' type='text' size='100' value='{$options['browserid_login_html']}' />";
		}

		// Logout HTML option
		function Option_logout_html() {
			$options = get_option('browserid_options');
			if (empty($options['browserid_logout_html']))
				$options['browserid_logout_html'] = null;
			echo "<input id='browserid_logout_html' name='browserid_options[browserid_logout_html]' type='text' size='100' value='{$options['browserid_logout_html']}' />";
		}

		// Should new users be created automatically with the 
		// email address for the username.
		function Option_auto_create_new_users() {
			$options = get_option('browserid_options');
			$chk = (isset($options['browserid_auto_create_new_users']) && $options['browserid_auto_create_new_users'] ? " checked='checked'" : '');
			echo "<input id='browserid_auto_create_new_users' name='browserid_options[browserid_auto_create_new_users]' type='checkbox'" . $chk. "/>";
		}

		// New user redir URL option
		function Option_newuser_redir() {
			$options = get_option('browserid_options');
			if (empty($options['browserid_newuser_redir']))
				$options['browserid_newuser_redir'] = null;
			echo "<input id='browserid_newuser_redir' name='browserid_options[browserid_newuser_redir]' type='text' size='100' value='{$options['browserid_newuser_redir']}' />";
			echo '<br />' . __('Default User Profile', c_bid_text_domain);
		}

		// Login redir URL option
		function Option_login_redir() {
			$options = get_option('browserid_options');
			if (empty($options['browserid_login_redir']))
				$options['browserid_login_redir'] = null;
			echo "<input id='browserid_login_redir' name='browserid_options[browserid_login_redir]' type='text' size='100' value='{$options['browserid_login_redir']}' />";
			echo '<br />' . __('Default WordPress dashboard', c_bid_text_domain);
		}

		// Enable comments integration
		function Option_comments() {
			$options = get_option('browserid_options');
			$chk = (isset($options['browserid_comments']) && $options['browserid_comments'] ? " checked='checked'" : '');
			echo "<input id='browserid_comments' name='browserid_options[browserid_comments]' type='checkbox'" . $chk. "/>";
			echo '<strong>Beta!</strong>';
		}

		// Enable bbPress integration
		function Option_bbpress() {
			$options = get_option('browserid_options');
			$chk = (isset($options['browserid_bbpress']) && $options['browserid_bbpress'] ? " checked='checked'" : '');
			echo "<input id='browserid_bbpress' name='browserid_options[browserid_bbpress]' type='checkbox'" . $chk. "/>";
			echo '<strong>Beta!</strong>';
			echo '<br />' . __('Enables anonymous posting implicitly', c_bid_text_domain);
		}

		// Comment HTML option
		function Option_comment_html() {
			$options = get_option('browserid_options');
			if (empty($options['browserid_comment_html']))
				$options['browserid_comment_html'] = null;
			echo "<input id='browserid_comment_html' name='browserid_options[browserid_comment_html]' type='text' size='100' value='{$options['browserid_comment_html']}' />";
		}

		// Verification server option
		function Option_vserver() {
			$options = get_option('browserid_options');
			if (empty($options['browserid_vserver']))
				$options['browserid_vserver'] = null;
			echo "<input id='browserid_vserver' name='browserid_options[browserid_vserver]' type='text' size='100' value='{$options['browserid_vserver']}' />";
			echo '<br />' . __('Default https://verifier.login.persona.org/verify', c_bid_text_domain);
		}

		// No valid until option
		function Option_novalid() {
			$options = get_option('browserid_options');
			$chk = (isset($options['browserid_novalid']) && $options['browserid_novalid'] ? " checked='checked'" : '');
			echo "<input id='browserid_novalid' name='browserid_options[browserid_novalid]' type='checkbox'" . $chk. "/>";
			echo '<strong>' . __('Security risk!', c_bid_text_domain) . '</strong>';
		}

		// No SSL verify option
		function Option_noverify() {
			$options = get_option('browserid_options');
			$chk = (isset($options['browserid_noverify']) && $options['browserid_noverify'] ? " checked='checked'" : '');
			echo "<input id='browserid_noverify' name='browserid_options[browserid_noverify]' type='checkbox'" . $chk. "/>";
			echo '<strong>' . __('Security risk!', c_bid_text_domain) . '</strong>';
		}

		// Debug option
		function Option_debug() {
			$options = get_option('browserid_options');
			$chk = (isset($options['browserid_debug']) && $options['browserid_debug'] ? " checked='checked'" : '');
			echo "<input id='browserid_debug' name='browserid_options[browserid_debug]' type='checkbox'" . $chk. "/>";
			echo '<strong>' . __('Security risk!', c_bid_text_domain) . '</strong>';
		}

		// Only allow Persona logins
		function Option_browserid_only_auth() {
			$options = get_option('browserid_options');
			$chk = (isset($options['browserid_only_auth']) && $options['browserid_only_auth'] ? " checked='checked'" : '');
			echo "<input id='browserid_only_auth' name='browserid_options[browserid_only_auth]' type='checkbox'" . $chk. "/>";
		}

		// Render options page
		function Administration() {
?>
			<div class="wrap">
				<h2><?php _e('Mozilla Persona', c_bid_text_domain); ?></h2>
				<form method="post" action="options.php">
					<?php settings_fields('browserid_options'); ?>
					<?php do_settings_sections('browserid'); ?>
					<p class="submit">
						<input type="submit" class="button-primary" value="<?php _e('Save Changes') ?>" />
					</p>
				</form>
			</div>
<?php
			if ($this->debug) {
				$options = get_option('browserid_options');
				$request = get_option(c_bid_option_request);
				$response = get_option(c_bid_option_response);
				if (is_wp_error($response))
					$result = $response;
				else
					$result = json_decode($response['body'], true);

				echo '<p><strong>Site URL</strong>: ' . get_site_url() . ' (WordPress address / folder)</p>';
				echo '<p><strong>Home URL</strong>: ' . get_home_url() . ' (Blog address / Home page)</p>';

				if (!empty($result) && !is_wp_error($result)) {
					echo '<p><strong>PHP Time</strong>: ' . time() . ' > ' . date('c', time()) . '</p>';
					echo '<p><strong>Assertion valid until</strong>: ' . $result['expires'] . ' > ' . date('c', $result['expires'] / 1000) . '</p>';
				}

				echo '<p><strong>PHP audience</strong>: ' . $_SERVER['HTTP_HOST'] . '</p>';
				echo '<script type="text/javascript">';
				echo 'document.write("<p><strong>JS audience</strong>: " + window.location.hostname + "</p>");';
				echo '</script>';

				echo '<br /><pre>Options=' . htmlentities(print_r($options, true)) . '</pre>';
				echo '<br /><pre>BID request=' . htmlentities(print_r($request, true)) . '</pre>';
				echo '<br /><pre>BID response=' . htmlentities(print_r($response, true)) . '</pre>';
				echo '<br /><pre>PHP request=' . htmlentities(print_r($_REQUEST, true)) . '</pre>';
				echo '<br /><pre>PHP server=' . htmlentities(print_r($_SERVER, true)) . '</pre>';
			}
			else {
				delete_option(c_bid_option_request);
				delete_option(c_bid_option_response);
			}
		}

		function http_api_curl($handle) {
			curl_setopt($handle, CURLOPT_CAINFO, dirname(__FILE__) . '/cacert.pem');
		}

		// Check environment
		function Check_prerequisites() {
			// Check WordPress version
			global $wp_version;
			if (version_compare($wp_version, '3.1') < 0)
				die('Mozilla Persona requires at least WordPress 3.1');

			// Check basic prerequisities
			self::Check_function('add_action');
			self::Check_function('wp_enqueue_script');
			self::Check_function('json_decode');
			self::Check_function('parse_url');
			self::Check_function('md5');
			self::Check_function('wp_remote_post');
			self::Check_function('wp_remote_get');
		}

		function Check_function($name) {
			if (!function_exists($name))
				die('Required WordPress function "' . $name . '" does not exist');
		}
	}
}

// Define widget
class BrowserID_Widget extends WP_Widget {
	// Widget constructor
	function BrowserID_Widget() {
		$widget_ops = array(
			'classname' => 'browserid_widget',
			'description' => __('Mozilla Persona login button', c_bid_text_domain)
		);
		$this->WP_Widget('BrowserID_Widget', 'Mozilla Persona', $widget_ops);
	}

	// Widget contents
	function widget($args, $instance) {
		extract($args);
		$title = apply_filters('widget_title', $instance['title']);
		echo $before_widget;
		if (!empty($title))
			echo $before_title . $title . $after_title;

		echo "<ul><li class='only-child'>" . M66BrowserID::Get_loginout_html() . "</li></ul>";
		echo $after_widget;
	}

	// Update settings
	function update($new_instance, $old_instance) {
		$instance = $old_instance;
		$instance['title'] = strip_tags($new_instance['title']);
		return $instance;
	}

	// Render settings
	function form($instance) {
		if (empty($instance['title']))
			$instance['title'] = null;
?>
		<p>
			<label for="<?php echo $this->get_field_id('title'); ?>"><?php _e('Title:'); ?></label>
			<input class="widefat" id="<?php echo $this->get_field_id('title'); ?>" name="<?php echo $this->get_field_name('title'); ?>" type="text" value="<?php echo esc_attr($instance['title']); ?>" />
		</p>
<?php
	}
}

// Check pre-requisites
M66BrowserID::Check_prerequisites();

// Start plugin
global $m66browserid;
if (empty($m66browserid)) {
	$m66browserid = new M66BrowserID();
	register_activation_hook(__FILE__, array(&$m66browserid, 'Activate'));
}

// Template tag "mozilla_persona"
if (!function_exists('mozilla_persona')) {
	function mozilla_persona() {
		echo M66BrowserID::Get_loginout_html();
	}
}

// Template tag "browserid_loginout"
if (!function_exists('browserid_loginout')) {
	function browserid_loginout() {
		echo M66BrowserID::Get_loginout_html();
	}
}

if (!function_exists('new_user_notification')) {
	function wp_new_user_notification($user_id, $plaintext_pass = '') {
		$user = get_userdata( $user_id );

		$user_login = stripslashes($user->user_login);
		$user_email = stripslashes($user->user_email);

		// The blogname option is escaped with esc_html on the way into the database in sanitize_option
		// we want to reverse this for the plain text arena of emails.
		$blogname = wp_specialchars_decode(get_option('blogname'), ENT_QUOTES);

		$message  = sprintf(__('New user registration on your site %s:'), $blogname) . "\r\n\r\n";
		$message .= sprintf(__('Username: %s'), $user_login) . "\r\n\r\n";
		$message .= sprintf(__('E-mail: %s'), $user_email) . "\r\n";

		@wp_mail(get_option('admin_email'), sprintf(__('[%s] New User Registration'), $blogname), $message);

		if ( empty($plaintext_pass) )
			return;

		$message  = sprintf(__('Username: %s'), $user_login) . "\r\n";
		$title = '';

		// Get plugin options
		$options = get_option('browserid_options');

		// XXX Collapse this in to the Get_browserid_only_auth
		if ((isset($options['browserid_only_auth']) && 
					$options['browserid_only_auth'])) {
			$message .= sprintf(__('%s uses Mozilla Persona to sign in and does not use passwords'), $blogname) . "\r\n";
			$title .= sprintf(__('[%s] Your username'), $blogname);
		} else {
			$message .= sprintf(__('Password: %s'), $plaintext_pass) . "\r\n";
			$title .= sprintf(__('[%s] Your username and password'), $blogname);
		}
		$message .= wp_login_url() . "\r\n";

		wp_mail($user_email, $title, $message);
	}
}

?>
