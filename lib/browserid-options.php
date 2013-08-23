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
		private $options_to_validate = null;

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
				if (! $field['https_only'] || $this->Is_https()) {

					add_settings_field($field_name, $field['title'],
							array(&$this, $field['display_func']), 
									$field['page'], $field['section']);

					if (isset($field['validation_func'])) {
						add_filter('persona_validation-' . $field_name,
								array(&$this, $field['validation_func']));
					}
				}
			}
		}

		public function Register_general_tab() {
			$this->plugin_settings_tabs[$this->general_settings_key] = 'General';

			register_setting($this->general_settings_key, 
					$this->general_settings_key, array(&$this, 'Validate_input'));

			add_settings_section('section_general', 'General Plugin Settings', 
					array(&$this, 'General_settings_description'), $this->general_settings_key);
		}

		private function Register_general_fields() {
			$this->Add_general_settings_field('browserid_sitename', 
					__('Site name:', c_bid_text_domain), 
					'Print_sitename',
					false,
					'Trim_input');

			$this->Add_general_settings_field('browserid_sitelogo', 
					__('Site logo:', c_bid_text_domain), 
					'Print_sitelogo',
					false,
					'Validate_sitelogo');

			$this->Add_general_settings_field('browserid_background_color', 
					__('Dialog background color:', c_bid_text_domain), 
					'Print_background_color');

			$this->Add_general_settings_field('browserid_terms_of_service', 
					__('Terms of service:', c_bid_text_domain), 
					'Print_terms_of_service',
					false,
					'Validate_terms_of_service');

			$this->Add_general_settings_field('browserid_privacy_policy', 
					__('Privacy policy:', c_bid_text_domain), 
					'Print_privacy_policy',
					false,
					'Validate_privacy_policy');

			$this->Add_general_settings_field('browserid_only_auth', 
					__('Disable non-Persona logins:', c_bid_text_domain), 
					'Print_browserid_only_auth');

			$this->Add_general_settings_field('browserid_button_color', 
					__('Login button color:', c_bid_text_domain), 
					'Print_button_color');

			$this->Add_general_settings_field('browserid_login_html', 
					__('Login button HTML:', c_bid_text_domain), 
					'Print_login_html',
					false,
					'Trim_input');

			$this->Add_general_settings_field('browserid_logout_html', 
					__('Logout button HTML:', c_bid_text_domain), 
					'Print_logout_html',
					false,
					'Trim_input');

			$this->Add_general_settings_field('browserid_login_redir', 
					__('Login redirection URL:', c_bid_text_domain), 
					'Print_login_redir',
					false,
					'Trim_input');

			$this->Add_general_settings_field('browserid_comments', 
					__('Enable for comments:', c_bid_text_domain), 
					'Print_comments');

			$this->Add_general_settings_field('browserid_comment_html', 
					__('Comment button HTML:', c_bid_text_domain), 
					'Print_comment_html',
					false,
					'Trim_input');

			$this->Add_general_settings_field('browserid_bbpress', 
					__('Enable bbPress integration:', c_bid_text_domain), 
					'Print_bbpress');
		}

		public function General_settings_description() {
			// Nothing to print here!
		}

		private function Add_general_settings_field($field_name, $title, 
				$display_func, $https_only = false, $validation_func = null) {
			$setting = array(
				'page' => $this->general_settings_key,
				'section' => 'section_general',
				'title' => $title,
				'display_func' => $display_func,
				'https_only' => $https_only,
				'validation_func' => $validation_func
			);
			$this->fields[$field_name] = $setting;
		}


		public function Register_advanced_tab() {
			$this->plugin_settings_tabs[$this->advanced_settings_key] = 'Advanced';

			register_setting($this->advanced_settings_key, 
					$this->advanced_settings_key, array(&$this, 'Validate_input'));

			add_settings_section('section_advanced', 'Advanced Plugin Settings', 
					array(&$this, 'Advanced_settings_description'), $this->advanced_settings_key);
		}

		private function Register_advanced_fields() {
			$this->Add_advanced_settings_field('browserid_persona_source', 
					__('Persona source:', c_bid_text_domain), 
					'Print_persona_source',
					false,
					'Validate_persona_source');

			$this->Add_advanced_settings_field('browserid_vserver', 
					__('Verification server:', c_bid_text_domain), 
					'Print_vserver',
					false,
					'Validate_vserver');

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

		public function Validate_input($input) {
			$this->options_to_validate = $input;
			foreach( $input as $key => $value ) {
				$input[$key] = apply_filters( 'persona_validation-' . $key, $value );
			}
			$this->options_to_validate = null;

			return $input;
		}

		private function Add_advanced_settings_field($field_name, $title, 
					$display_func, $https_only = false, $validation_func = null) {
			$field_config = array(
				'page' => $this->advanced_settings_key,
				'section' => 'section_advanced',
				'title' => $title,
				'display_func' => $display_func,
				'https_only' => $https_only,
				'validation_func' => $validation_func
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
			$this->Print_text_input(array(
				'name' => 'browserid_sitename', 
				'default_value' => $this->Get_sitename()
			));
		}

		public function Get_sitename() {
			$name = $this->Get_field_value('browserid_sitename');
			if (empty($name))
				$name = get_bloginfo('name');
			return $name;
		}



		public function Print_sitelogo() {
			$this->Print_file_picker_input(array(
				'name' => 'browserid_sitelogo', 
				'description' => __('Must be a data URI or image served over HTTPS', c_bid_text_domain),
				'type' => 'image',
				'title' => __('Site Logo', c_bid_text_domain)
			));
		}

		public function Get_sitelogo() {
			return $this->Get_field_value('browserid_sitelogo');
		}

		public function Validate_sitelogo($value) {
			$value = trim($value);
			if ($value === '') return '';

			if ($this->Is_absolute_path_url($value)) {
				// absolute paths are only allowed if site is HTTPS
				if ($this->Is_https()) return $value;
				add_settings_error('browserid_sitelogo',
							'browserid_sitelogo',
							__('sitelogo URLs beginning with / must be served over https', c_bid_text_domain),
							'error');
				return '';
			}

			if ($this->Is_http_url($value)) {
				add_settings_error('browserid_sitelogo',
							'browserid_sitelogo',
							__('sitelogo must begin with https, / or data:image', c_bid_text_domain),
							'error');
				return '';
			}

			if ($this->Is_https_url($value)) return esc_url_raw($value, array('https'));
			if ($this->Is_image_data_uri($value)) return $value;

			add_settings_error('browserid_sitelogo',
						'browserid_sitelogo',
						__('Invalid sitelogo', c_bid_text_domain),
						'error');
			return '';
		}


		public function Print_background_color() {
			$this->Print_text_input(array(
				'name' => 'browserid_background_color', 
				'class' => 'js-persona__color-picker'
			));
		}

		public function Get_background_color() {
			return $this->Get_field_value('browserid_background_color');
		}


		public function Print_terms_of_service() {
			$this->Print_file_picker_input(array(
				'name' => 'browserid_terms_of_service', 
				'description' => __('Must be defined with Privacy policy', c_bid_text_domain),
				'type' => 'text',
				'title' => __('Terms of Service', c_bid_text_domain)
			));
		}

		public function Get_terms_of_service() {
			return $this->Get_field_value('browserid_terms_of_service');
		}

		public function Validate_terms_of_service($value) {
			$value = trim($value);
			if ($value === '') return '';

			$privacy_policy = trim($this->options_to_validate['browserid_privacy_policy']);
			if (! $privacy_policy || $privacy_policy === '') {
				add_settings_error('browserid_terms_of_service',
							'browserid_terms_of_service',
							__('Terms of Service must be set with Privacy Policy', c_bid_text_domain),
							'error');
				return '';
			}

			if ($this->Is_http_or_https_url($value)) return esc_url_raw($value, array('http', 'https'));
			if ($this->Is_absolute_path_url($value)) return esc_url_raw($value);

			add_settings_error('browserid_terms_of_service',
						'browserid_terms_of_service',
						__('Invalid Terms of Service', c_bid_text_domain),
						'error');
			return '';
		}


		public function Print_privacy_policy() {
			$this->Print_file_picker_input(array(
				'name' => 'browserid_privacy_policy', 
				'description' => __('Must be and must be defined with Terms of service', c_bid_text_domain),
				'type' => 'text',
				'title' => __('Privacy Policy', c_bid_text_domain)
			));
		}

		public function Get_privacy_policy() {
			return $this->Get_field_value('browserid_privacy_policy');
		}

		public function Validate_privacy_policy($value) {
			$value = trim($value);
			if ($value === '') return '';

			$terms_of_service = trim($this->options_to_validate['browserid_terms_of_service']);
			if (! $terms_of_service || $terms_of_service === '') {
				add_settings_error('browserid_privacy_policy',
							'browserid_privacy_policy',
							__('Privacy Policy must be set with Terms of Service', c_bid_text_domain),
							'error');
				return '';
			}

			if ($this->Is_http_or_https_url($value)) return esc_url_raw($value, array('http', 'https'));
			if ($this->Is_absolute_path_url($value)) return esc_url_raw($value);

			add_settings_error('browserid_privacy_policy',
						'browserid_privacy_policy',
						__('Invalid Privacy Policy', c_bid_text_domain),
						'error');
			return '';
		}




		public function Print_login_html() {
			$this->Print_text_input(array(
				'name' => 'browserid_login_html', 
				'default_value' => $this->Get_login_html()
			));
		}

		public function Get_login_html() {
			return $this->Get_field_value('browserid_login_html', 
					__('Sign in with your email', c_bid_text_domain));
		}




		public function Print_logout_html() {
			$this->Print_text_input(array(
				'name' => 'browserid_logout_html', 
				'default_value' => $this->Get_logout_html()
			));
		}

		public function Get_logout_html() {
			return $this->Get_field_value('browserid_logout_html', 
					__('Logout', c_bid_text_domain));
		}




		public function Print_login_redir() {
			$this->Print_text_input(array(
				'name' => 'browserid_login_redir',
				'description' => __('Default WordPress dashboard', c_bid_text_domain)
			));
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
			$this->Print_text_input(array(
				'name' => 'browserid_comment_html', 
				'default_value' => $this->Get_comment_html()
			));
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
			$this->Print_text_input(array(
				'name' => 'browserid_persona_source', 
				'default_value' => $this->Get_persona_source(),
				'description' => __('Default', c_bid_text_domain) . ' ' . c_bid_source
			));
		}

		public function Get_persona_source() {
			return $this->Get_field_value('browserid_persona_source', c_bid_source);
		}

		public function Validate_persona_source($value) {
			$value = trim($value);
			if ($value === '') return '';

			if ($this->Is_http_or_https_url($value)) return esc_url_raw($value, array('http', 'https'));

			add_settings_error('browserid_persona_source',
						'browserid_persona_source',
						__('Persona source must be an http or https URL', c_bid_text_domain),
						'error');
			return '';
		}



		public function Print_vserver() {
			$this->Print_text_input(array(
				'name' => 'browserid_vserver', 
				'default_value' => $this->Get_vserver(),
				'description' => __('Default', c_bid_text_domain) . ' ' . c_bid_verifier . '/verify'
			));
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

		public function Validate_vserver($value) {
			$value = trim($value);
			if ($value === '') return '';

			if ($this->Is_http_or_https_url($value)) return esc_url_raw($value, array('http', 'https'));

			add_settings_error('browserid_vserver',
						'browserid_vserver',
						__('Verification server must be an http or https URL', c_bid_text_domain),
						'error');
			return '';
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

		private function Get_passed_option($options, $option_name) {
			return isset($options[$option_name]) ? $options[$option_name] : '';
		}


		private function Print_file_picker_input($options) {
			$options['extra_html'] = 
					$this->Build_element_html('button', array(
						'for' => 
								$this->Get_passed_option($options, 'name'),
						'data-title' => 
								$this->Get_passed_option($options, 'title'),
						'data-type' => 
								$this->Get_passed_option($options, 'type'),
						'class' => 
								'js-persona__file-picker',
						'html' =>
								__('Choose from media', c_bid_text_domain)
					));
			$this->Print_text_input($options);
		}

		// Print a text input for a plugin option
		private function Print_text_input($options) {
			$name = $this->Get_passed_option($options, 'name');
			$default_value = 
					$this->Get_passed_option($options, 'default_value');

			$this->Print_element('input', array(
				'id' => $name,
				'type' => 'text',
				'size' => '50',
				'value' => 
					htmlspecialchars($this->Get_field_value($options['name'], 
										$default_value), ENT_QUOTES),
				'name' => 
					$this->Get_field_option_name($name) . '[' . $name . ']',
				'class' => $this->Get_passed_option($options, 'class')
			));

			echo $this->Get_passed_option($options, 'extra_html');

			$description = $this->Get_passed_option($options, 'description');
			if ($description) {
				echo '<br />' . $description;
			}
		}
		
		private function Print_checkbox_input($field_name) {
			$option_page = $this->Get_field_option_name($field_name);

			$attributes = array(
				'type' => 'checkbox',
				'id' => $field_name,
				'name' => $option_page . '[' . $field_name . ']'
			);

			$options = get_option($option_page);
			$chk = isset($options[$field_name]) && $options[$field_name];
			if ($chk) {
				$attributes['checked'] = 'checked';
			}

			$this->Print_element('input', $attributes);
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


		/**
		* Build a string of HTML
		* @element_name - name of the element
		* @attributes - list of attributes to add to the element.
		* @attributes.html - 'special' attribute used to specify
		*		the element's innerHtml.
		*/
		private function Build_element_html(
							$element_name, $attributes) {
			$attribute_text = ' ';
			foreach ($attributes as $attribute_name => $attribute_value) {
				if (! empty($attribute_value) && $attribute_name !== "html") {
					$attribute_text .= 
						' ' . $attribute_name . '="' . esc_attr($attribute_value) . '"';
				}
			}

			$inner_html = $this->Get_passed_option($attributes, 'html');

			$text_to_print = '<' . $element_name . $attribute_text . '>' 
									. $inner_html . '</' . $element_name . '>';
			return $text_to_print;
		}

		private function Print_element(
							$element_name, $attributes) {
			echo $this->Build_element_html(
								$element_name, $attributes);
		}


		// These functions are for validation
		private function Is_https() {
			return (!empty($_SERVER['HTTPS']) 
						&& $_SERVER['HTTPS'] !== 'off' || 
							$_SERVER['SERVER_PORT'] == 443);

		}

		private function Is_absolute_path_url($value) {
			return preg_match('/^\/[^\/]/', $value);
		}

		private function Is_http_url($value) {
			return preg_match('/^http:\/\//', $value);
		}

		private function Is_https_url($value) {
			return preg_match('/^https:\/\//', $value);
		}

		private function Is_http_or_https_url($value) {
			return preg_match('/^http(s)?:\/\//', $value);
		}

		private function Is_image_data_uri($value) {
			return preg_match('/^data:image\//', $value);
		}
		
		public function Trim_input($value) {
			return trim($value);
		}
	}
}
?>
