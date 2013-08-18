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

include_once('browserid-constants.php');

if (!class_exists('MozillaPersonaOptions')) {
	class MozillaPersonaOptions {
		private $plugin_options_key = 'browserid_options';
		private $general_settings_key = 'browserid_general_options';
		private $advanced_settings_key = 'browserid_advanced_options';

		// fields is a dictionary of fields, the key to each value 
		//		is the field's name as stored in the database.
		// Each setting is made up of:
		// 'page' => page where field is displayed
		// 'section' => section of the page where the field is displayed
		// 'title' => field's title in the field's page
		// 'display_func' => function to display field in settings page.
		private $fields = null;

		public function  __construct() {
			$fields = array();
		}

		// The general approach is to register each setting each time a page is 
		// loaded. When a setting is registered, it's configuration is stored 
		// into the settings dictionary. 
		public function Init() {
			$this->Load_settings();

			$this->Register_general_fields();
			$this->Register_advanced_fields();

			if (is_admin()) {
				add_action('admin_init', array(&$this, 'Register_general_tab'));
				add_action('admin_init', array(&$this, 'Register_advanced_tab'));
				add_action('admin_init', array(&$this, 'Register_all_fields'));

				add_action('admin_menu', 
						array(&$this, 'Add_persona_to_settings_list_action'));
			}
		}

		public function Add_persona_to_settings_list_action() {
			if (function_exists('add_options_page'))
				add_options_page(
					__('Mozilla Persona', c_bid_text_domain) . ' ' . __('Administration', c_bid_text_domain),
					__('Mozilla Persona', c_bid_text_domain),
					'manage_options',
					$this->plugin_options_key,
					array(&$this, 'Render_admin_page'));
		}

		private function Load_settings() {
			$this->general_settings = (array) get_option( $this->general_settings_key );
			$this->advanced_settings = (array) get_option( $this->advanced_settings_key );

			// Merge with defaults
			$this->general_settings = array_merge( array(
				'general_option' => 'General value'
			), $this->general_settings );

			$this->advanced_settings = array_merge( array(
				'advanced_option' => 'Advanced value'
			), $this->advanced_settings );
		}

		public function Register_all_fields() {
			foreach ($this->fields as $field_name => $field) {
				add_settings_field($field_name, $field['title'],
						array(&$this, $field['display_func']), $field['page'], $field['section']);
			}
		}

		public function Register_general_tab() {
			$this->plugin_settings_tabs[$this->general_settings_key] = 'General';

			register_setting($this->general_settings_key, $this->general_settings_key);

			add_settings_section('section_general', 'General Plugin Settings', 
					array(&$this, 'General_settings_description'), $this->general_settings_key);
		}

		private function Register_general_fields() {
			$this->Add_general_settings_field('browserid_sitename', 
					__('Site name:', c_bid_text_domain), 
					'Print_sitename');

			$this->Add_general_settings_field('browserid_sitelogo', 
					__('Site logo:', c_bid_text_domain), 
					'Print_sitelogo');

			$this->Add_general_settings_field('browserid_background_color', 
					__('Dialog background color:', c_bid_text_domain), 
					'Print_background_color');

			$this->Add_general_settings_field('browserid_terms_of_service', 
					__('Terms of service:', c_bid_text_domain), 
					'Print_terms_of_service');

			$this->Add_general_settings_field('browserid_privacy_policy', 
					__('Privacy policy:', c_bid_text_domain), 
					'Print_privacy_policy');

			$this->Add_general_settings_field('browserid_only_auth', 
					__('Disable non-Persona logins:', c_bid_text_domain), 
					'Print_browserid_only_auth');

			$this->Add_general_settings_field('browserid_button_color', 
					__('Login button color:', c_bid_text_domain), 
					'Print_button_color');

			$this->Add_general_settings_field('browserid_login_html', 
					__('Login button HTML:', c_bid_text_domain), 
					'Print_login_html');

			$this->Add_general_settings_field('browserid_logout_html', 
					__('Logout button HTML:', c_bid_text_domain), 
					'Print_logout_html');

			$this->Add_general_settings_field('browserid_login_redir', 
					__('Login redirection URL:', c_bid_text_domain), 
					'Print_login_redir');

			$this->Add_general_settings_field('browserid_comments', 
					__('Enable for comments:', c_bid_text_domain), 
					'Print_comments');

			$this->Add_general_settings_field('browserid_comment_html', 
					__('Comment button HTML:', c_bid_text_domain), 
					'Print_comment_html');

			$this->Add_general_settings_field('browserid_bbpress', 
					__('Enable bbPress integration:', c_bid_text_domain), 
					'Print_bbpress');
		}

		public function General_settings_description() {
			// Nothing to print here!
		}

		private function Add_general_settings_field($field_name, $title, $display_func) {
			$setting = array(
				'page' => $this->general_settings_key,
				'section' => 'section_general',
				'title' => $title,
				'display_func' => $display_func
			);
			$this->fields[$field_name] = $setting;
		}


		public function Register_advanced_tab() {
			$this->plugin_settings_tabs[$this->advanced_settings_key] = 'Advanced';

			register_setting($this->advanced_settings_key, $this->advanced_settings_key);

			add_settings_section('section_advanced', 'Advanced Plugin Settings', 
					array(&$this, 'Advanced_settings_description'), $this->advanced_settings_key);
		}

		private function Register_advanced_fields() {
			$this->Add_advanced_settings_field('browserid_persona_source', 
					__('Persona source:', c_bid_text_domain), 
					'Print_persona_source');

			$this->Add_advanced_settings_field('browserid_vserver', 
					__('Verification server:', c_bid_text_domain), 
					'Print_vserver');

			$this->Add_advanced_settings_field('browserid_debug', 
					__('Debug mode:', c_bid_text_domain), 
					'Print_debug');
		}

		public function Advanced_settings_description() {
			echo '<p class="persona__warning persona__warning-heading">';
			echo __('Changing these options can cause you to be locked out of your site!', 
						c_bid_text_domain);
			echo '</p>';
		}


		private function Add_advanced_settings_field($field_name, $title, $display_func) {
			$field_config = array(
				'page' => $this->advanced_settings_key,
				'section' => 'section_advanced',
				'title' => $title,
				'display_func' => $display_func
			);
			$this->fields[$field_name] = $field_config;
		}




		public function Deactivate() {
			if (get_option($this->general_settings_key)) delete_option($this->general_settings_key);
			if (get_option($this->advanced_settings_key)) delete_option($this->advanced_settings_key);
		}

		public function Render_admin_page() {
			$tab = isset( $_GET['tab'] ) ? $_GET['tab'] : $this->general_settings_key;
			?>
			<div class="wrap">
				<?php screen_icon(); ?>
				<h2><?php _e('Mozilla Persona', c_bid_text_domain); ?></h2>
				<?php $this->plugin_options_tabs(); ?>
				<form method="post" action="options.php">
					<?php wp_nonce_field( 'update-options' ); ?>
					<?php settings_fields($tab); ?>
					<?php do_settings_sections($tab); ?>
					<?php submit_button(); ?>
				</form>
			</div>
<?php
			if ($this->Is_debug() && $tab === $this->advanced_settings_key) {
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

				/*echo '<p><strong>PHP audience</strong>: 
				' . htmlentities($this->audience) . '</p>';*/
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

		public function plugin_options_tabs() {
			$current_tab = isset( $_GET['tab'] ) ? $_GET['tab'] : $this->general_settings_key;

			echo '<h2 class="nav-tab-wrapper">';
			foreach ( $this->plugin_settings_tabs as $tab_key => $tab_caption ) {
				$active = $current_tab == $tab_key ? 'nav-tab-active' : '';
				echo '<a class="nav-tab ' . $active . '" href="?page=' . $this->plugin_options_key . '&tab=' . $tab_key . '">' . $tab_caption . '</a>';
			}
			echo '</h2>';
		}



		public function Print_sitename() {
			$this->Print_text_input('browserid_sitename', 
					$this->Get_sitename());
		}

		public function Get_sitename() {
			$name = $this->Get_field_value('browserid_sitename');
			if (empty($name))
				$name = get_bloginfo('name');
			return $name;
		}



		public function Print_sitelogo() {
			$this->Print_text_input('browserid_sitelogo', null,
					__('Absolute path, works only with SSL', c_bid_text_domain));
		}

		public function Get_sitelogo() {
			// sitelogo is only valid with SSL connections
			if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443)
				return $this->Get_field_value('browserid_sitelogo');
			return '';
		}



		public function Print_background_color() {
			$this->Print_text_input('browserid_background_color', null,
					__('3 or 6 character hex value. e.g. #333 or #333333', c_bid_text_domain));
		}

		public function Get_background_color() {
			return $this->Get_field_value('browserid_background_color');
		}



		public function Print_terms_of_service() {
			$this->Print_text_input('browserid_terms_of_service', null,
					__('URL or absolute path, works only with SSL and must be defined together with Privacy policy', c_bid_text_domain));
		}

		public function Get_terms_of_service() {
			return $this->Get_field_value('browserid_terms_of_service');
		}



		public function Print_privacy_policy() {
			$this->Print_text_input('browserid_privacy_policy', null,
					__('URL or absolute path, works only with SSL and must be and must be defined together with Terms of service', c_bid_text_domain));
		}

		public function Get_privacy_policy() {
			return $this->Get_field_value('browserid_privacy_policy');
		}




		public function Print_login_html() {
			$this->Print_text_input('browserid_login_html', 
					$this->Get_login_html());
		}

		public function Get_login_html() {
			return $this->Get_field_value('browserid_login_html', 
					__('Sign in with your email', c_bid_text_domain));
		}




		public function Print_logout_html() {
			$this->Print_text_input('browserid_logout_html', 
					$this->Get_logout_html());
		}

		public function Get_logout_html() {
			return $this->Get_field_value('browserid_logout_html', 
					__('Logout', c_bid_text_domain));
		}




		public function Print_login_redir() {
			$this->Print_text_input('browserid_login_redir', null,
					__('Default WordPress dashboard', c_bid_text_domain));
		}

		public function Get_login_redir() {
			return $this->Get_field_value('browserid_login_redir', null);
		}




		public function Print_comments($section) {
			$this->Print_checkbox_input('browserid_comments');
		}

		public function Is_comments() {
			return $this->Get_boolean_field_value('browserid_comments');
		}




		public function Print_comment_html() {
			$this->Print_text_input('browserid_comment_html', 
					$this->Get_comment_html());
		}

		public function Get_comment_html() {
			return $this->Get_field_value('browserid_comment_html', 
					__('Post comment', c_bid_text_domain));
		}



		public function Print_bbpress() {
			$this->Print_checkbox_input('browserid_bbpress');
			echo '<strong>Beta!</strong>';
			echo '<br />' . __('Enables anonymous posting implicitly', c_bid_text_domain);
		}

		public function Is_bbpress() {
			return $this->Get_boolean_field_value('browserid_bbpress');
		}



		public function Print_persona_source() {
			$this->Print_text_input('browserid_persona_source', 
					$this->Get_persona_source(),
					__('Default', c_bid_text_domain) . ' ' . c_bid_source);
		}

		public function Get_persona_source() {
			return $this->Get_field_value('browserid_persona_source', c_bid_source);
		}




		public function Print_vserver() {
			$this->Print_text_input('browserid_vserver', 
					$this->Get_vserver(),
					__('Default', c_bid_text_domain) . ' ' . c_bid_verifier . '/verify');
		}

		public function Get_vserver() {
			$vserver = $this->Get_field_value('browserid_vserver');
			$source = $this->Get_persona_source();

			if ($vserver) return $vserver;

			if ($source != c_bid_source)
				$vserver = $source . '/verify';
			else
				$vserver = c_bid_verifier . '/verify';

			return $vserver;
		}

		
		// The audience is a non-settable option
		public function Get_audience() {
			return $_SERVER['HTTP_HOST'];
		}


		public function Print_debug() {
			$this->Print_checkbox_input('browserid_debug');
			echo '<strong>' . __('Security risk!', c_bid_text_domain) . '</strong>';
		}

		public function Is_debug() {
			return $this->Get_boolean_field_value('browserid_debug');
		}




		public function Print_browserid_only_auth() {
			$this->Print_checkbox_input('browserid_only_auth');
		}

		public function Is_browserid_only_auth() {
			return $this->Get_boolean_field_value('browserid_only_auth');
		}




		public function Print_button_color() {
			echo "<ul>";
			$this->Print_persona_button_selection(
					__('Blue', c_bid_text_domain), 'blue');
			$this->Print_persona_button_selection(
					__('Black', c_bid_text_domain), 'dark');
			$this->Print_persona_button_selection(
					__('Orange', c_bid_text_domain), 'orange');
			echo "</ul>";
		}

		public function Get_button_color() {
			return $this->Get_field_value('browserid_button_color', 'blue');
		}

		private function Print_persona_button_selection($name, $value) {
			$color = $this->Get_button_color();
			$chk = ($color == $value ? " checked='checked'" : '');
?>
			<li class='persona-button--select-color'>
				<input name='<?php echo $this->Get_field_option_name('browserid_button_color'); ?>[browserid_button_color]' 
					class='persona-button--select-color-radio' 
					type='radio' value='<?php echo $value; ?>' <?php echo $chk; ?> /> 
				<label class='persona-button <?php echo $value; ?>'> 
					<span class='persona-button__text'><?php echo $name; ?></span> 
				</label> 
			</li>
<?php
		}



		// Print a text input for a plugin option
		private function Print_text_input($field_name, $default_value = null, $info = null) {
			$option_value = $this->Get_field_value($field_name, $default_value);

			echo sprintf("<input id='%s' name='%s[%s]' type='text' size='50' value='%s' />",
					$field_name,
					$this->Get_field_option_name($field_name),
					$field_name,
					htmlspecialchars($option_value, ENT_QUOTES));

			if ($info) {
				echo '<br />' . $info;
			}
		}

		private function Print_checkbox_input($field_name) {
			$option_page = $this->Get_field_option_name($field_name);
			$options = get_option($option_page);
			$chk = (isset($options[$field_name]) && $options[$field_name] ? " checked='checked'" : '');
			echo "<input id='" . $field_name . "' name='" . $option_page . "[". $field_name . "]' type='checkbox'" . $chk. "/>";
		}



		// Generic Get_field_value to get an option, if it is not set, return the 
		// default value
		private function Get_field_value($field_name, $default_value = '') {
			$option = get_option($this->Get_field_option_name($field_name));

			if (isset($option[$field_name]) 
					&& !empty($option[$field_name])) {
				return $option[$field_name];
			}
			return $default_value;
		}

		private function Get_boolean_field_value($field_name) {
			$option = get_option($this->Get_field_option_name($field_name));

			return (isset($option[$field_name]) && $option[$field_name]);
		}

		private function Get_field_option_name($field_name) {
			$field = $this->fields[$field_name];
			return $field['page'];
		}

	}
}
?>
