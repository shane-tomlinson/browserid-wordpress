<?php
/*
	Copyright (c) 2011, 2012, 2013 Shane Tomlinson, Marcel Bokhorst

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

include_once('constants.php');

if (!class_exists('MozillaPersonaOptions')) {
	class MozillaPersonaOptions {
		public function  __construct() {
		}

		public function Register_settings() {
			register_setting('browserid_options', 'browserid_options', null);

			add_settings_section('plugin_main', null, 
					array(&$this, 'Options_main'), 'browserid');

			$this->Add_settings_field('browserid_sitename', 
					__('Site name:', c_bid_text_domain), 
					'Print_sitename');

			$this->Add_settings_field('browserid_sitelogo', 
					__('Site logo:', c_bid_text_domain), 
					'Print_sitelogo');

			$this->Add_settings_field('browserid_background_color', 
					__('Dialog background color:', c_bid_text_domain), 
					'Print_background_color');

			$this->Add_settings_field('browserid_terms_of_service', 
					__('Terms of service:', c_bid_text_domain), 
					'Print_terms_of_service');

			$this->Add_settings_field('browserid_privacy_policy', 
					__('Privacy policy:', c_bid_text_domain), 
					'Print_privacy_policy');

			$this->Add_settings_field('browserid_only_auth', 
					__('Disable non-Persona logins:', c_bid_text_domain), 
					'Print_browserid_only_auth');

			$this->Add_settings_field('browserid_button_color', 
					__('Login button color:', c_bid_text_domain), 
					'Print_button_color');

			$this->Add_settings_field('browserid_login_html', 
					__('Login button HTML:', c_bid_text_domain), 
					'Print_login_html');

			$this->Add_settings_field('browserid_logout_html', 
					__('Logout button HTML:', c_bid_text_domain), 
					'Print_logout_html');

			$this->Add_settings_field('browserid_login_redir', 
					__('Login redirection URL:', c_bid_text_domain), 
					'Print_login_redir');

			$this->Add_settings_field('browserid_comments', 
					__('Enable for comments:', c_bid_text_domain), 
					'Print_comments');

			$this->Add_settings_field('browserid_comment_html', 
					__('Comment button HTML:', c_bid_text_domain), 
					'Print_comment_html');

			$this->Add_settings_field('browserid_bbpress', 
					__('Enable bbPress integration:', c_bid_text_domain), 
					'Print_bbpress');

			$this->Add_settings_field('browserid_persona_source', 
					__('Persona source:', c_bid_text_domain), 
					'Print_persona_source');

			$this->Add_settings_field('browserid_vserver', 
					__('Verification server:', c_bid_text_domain), 
					'Print_vserver');

			$this->Add_settings_field('browserid_debug', 
					__('Debug mode:', c_bid_text_domain), 
					'Print_debug');
		}

		public function Deactivate() {
			if(get_option('browserid_options'))
				delete_option('browserid_options');
		}

		// Main options section
		function Options_main() {
			// Empty
		}


		function Add_settings_field($field_name, $option_title, $display_func) {
			add_settings_field($field_name, $option_title,
					array(&$this, $display_func), 'browserid', 'plugin_main');
		}



		function Print_sitename() {
			$this->Print_text_input('browserid_sitename', 
					$this->Get_sitename());
		}

		function Get_sitename() {
			$name = $this->Get_option('browserid_sitename');
			if (empty($name))
				$name = get_bloginfo('name');
			return $name;
		}



		function Print_sitelogo() {
			$this->Print_text_input('browserid_sitelogo', null,
					__('Absolute path, works only with SSL', c_bid_text_domain));
		}

		function Get_sitelogo() {
			$options = get_option('browserid_options');
			// sitelogo is only valid with SSL connections
			if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443)
				return $this->Get_option('browserid_sitelogo');
			return '';
		}



		function Print_background_color() {
			$this->Print_text_input('browserid_background_color', null,
					__('3 or 6 character hex value. e.g. #333 or #333333', c_bid_text_domain));
		}

		function Get_background_color() {
			return $this->Get_option('browserid_background_color');
		}



		function Print_terms_of_service() {
			$this->Print_text_input('browserid_terms_of_service', null,
					__('URL or absolute path, works only with SSL and must be defined together with Privacy policy', c_bid_text_domain));
		}

		function Get_terms_of_service() {
			return $this->Get_option('browserid_terms_of_service');
		}



		function Print_privacy_policy() {
			$this->Print_text_input('browserid_privacy_policy', null,
					__('URL or absolute path, works only with SSL and must be and must be defined together with Terms of service', c_bid_text_domain));
		}

		function Get_privacy_policy() {
			return $this->Get_option('browserid_privacy_policy');
		}




		function Print_login_html() {
			$this->Print_text_input('browserid_login_html', 
					$this->Get_login_html());
		}

		function Get_login_html() {
			return $this->Get_option('browserid_login_html', 
					__('Sign in with your email', c_bid_text_domain));
		}




		function Print_logout_html() {
			$this->Print_text_input('browserid_logout_html', 
					$this->Get_logout_html());
		}

		function Get_logout_html() {
			return $this->Get_option('browserid_logout_html', 
					__('Logout', c_bid_text_domain));
		}




		function Print_login_redir() {
			$this->Print_text_input('browserid_login_redir', null,
					__('Default WordPress dashboard', c_bid_text_domain));
		}

		function Get_login_redir() {
			return $this->Get_option('browserid_login_redir', null);
		}




		function Print_comments() {
			$options = get_option('browserid_options');
			$chk = (isset($options['browserid_comments']) && $options['browserid_comments'] ? " checked='checked'" : '');
			echo "<input id='browserid_comments' name='browserid_options[browserid_comments]' type='checkbox'" . $chk. "/>";
		}

		function Is_comments() {
			return $this->Get_option('browserid_comments', false);
		}




		function Print_comment_html() {
			$this->Print_text_input('browserid_comment_html', 
					$this->Get_comment_html());
		}

		function Get_comment_html() {
			return $this->Get_option('browserid_comment_html', __('post comment', c_bid_text_domain));
		}



		function Print_bbpress() {
			$options = get_option('browserid_options');
			$chk = (isset($options['browserid_bbpress']) && $options['browserid_bbpress'] ? " checked='checked'" : '');
			echo "<input id='browserid_bbpress' name='browserid_options[browserid_bbpress]' type='checkbox'" . $chk. "/>";
			echo '<strong>Beta!</strong>';
			echo '<br />' . __('Enables anonymous posting implicitly', c_bid_text_domain);
		}

		function Is_bbpress() {
			$options = get_option('browserid_options');

			return isset($options['browserid_bbpress']) &&
						$options['browserid_bbpress'];
		}



		function Print_persona_source() {
			$this->Print_text_input('browserid_persona_source', 
					$this->Get_persona_source(),
					__('Default', c_bid_text_domain) . ' ' . c_bid_source);
		}

		function Get_persona_source() {
			return $this->Get_option('browserid_persona_source', c_bid_source);
		}




		function Print_vserver() {
			$this->Print_text_input('browserid_vserver', 
					$this->Get_vserver(),
					__('Default', c_bid_text_domain) . ' ' . c_bid_verifier . '/verify');
		}

		function Get_vserver() {
			$options = get_option('browserid_options');
			$source = self::Get_persona_source();

			if (isset($options['browserid_vserver']) && $options['browserid_vserver'])
				$vserver = $options['browserid_vserver'];
			else if ($source != c_bid_source)
				$vserver = $source . '/verify';
			else
				$vserver = c_bid_verifier . '/verify';

			return $vserver;
		}



		function Print_debug() {
			$options = get_option('browserid_options');
			$chk = (isset($options['browserid_debug']) && $options['browserid_debug'] ? " checked='checked'" : '');
			echo "<input id='browserid_debug' name='browserid_options[browserid_debug]' type='checkbox'" . $chk. "/>";
			echo '<strong>' . __('Security risk!', c_bid_text_domain) . '</strong>';
		}

		function Is_debug() {
			$options = get_option('browserid_options');
			return ((isset($options['browserid_debug']) && $options['browserid_debug']));
		}




		function Print_browserid_only_auth() {
			$options = get_option('browserid_options');
			$chk = (isset($options['browserid_only_auth']) && $options['browserid_only_auth'] ? " checked='checked'" : '');
			echo "<input id='browserid_only_auth' name='browserid_options[browserid_only_auth]' type='checkbox'" . $chk. "/>";
		}

		function Is_browserid_only_auth() {
			$options = get_option('browserid_options');

			return isset($options['browserid_only_auth']) && $options['browserid_only_auth'];
		}



		function Print_button_color() {
			echo "<ul>";
			$this->Print_persona_button_selection(
					__('Blue', c_bid_text_domain), 'blue');
			$this->Print_persona_button_selection(
					__('Black', c_bid_text_domain), 'dark');
			$this->Print_persona_button_selection(
					__('Orange', c_bid_text_domain), 'orange');
			echo "</ul>";
		}

		function Get_button_color() {
			return $this->Get_option('browserid_button_color', 'blue');
		}




		private function Print_persona_button_selection($name, $value) {
			$color = $this->Get_button_color();
			$chk = ($color == $value ? " checked='checked'" : '');

			echo "<li class='persona-button--select-color'>" .
					 "<input name='browserid_options[browserid_button_color]' " .
							"class='persona-button--select-color-radio'" .
							"type='radio' value='". $value ."'" . $chk. "/>" .
					 "<label class='persona-button " . $value ."'>" .
						 "<span class='persona-button__text'>" . $name . "</span>" .
					 "</label>" .
				 "</li>";
		}

		// Print a text input for a plugin option
		private function Print_text_input($option_name, $default_value = null, $info = null) {
			$option_value = $this->Get_option($option_name, $default_value);
			echo sprintf("<input id='%s' name='browserid_options[%s]' type='text' size='50' value='%s' />",
				$option_name,
				$option_name,
				htmlspecialchars($option_value, ENT_QUOTES));

			if ($info) {
				echo '<br />' . $info;
			}
		}

		// Generic Get_option to get an option, if it is not set, return the 
		// default value
		private function Get_option($option_name, $default_value = '') {
			$options = get_option('browserid_options');
			if (isset($options[$option_name]) 
					&& !empty($options[$option_name])) {
				return $options[$option_name];
			}
			return $default_value;
		}
	}
}
?>
