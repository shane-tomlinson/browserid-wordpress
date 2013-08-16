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

if (!class_exists('MozillaPersonaAdministration')) {
	class MozillaPersonaAdministration {
		private $browserid_only_auth = false;
		private $logged_in_user = null;
		private $ui = null;
		private $audience = null;
		private $is_debug = false;
		private $logout_html = null;

		public function __construct($options) {
			$this->browserid_only_auth = $options['browserid_only_auth'];
			$this->logged_in_user = $options['logged_in_user'];
			$this->ui = $options['ui'];
			$this->is_debug = $options['is_debug'];
			$this->audience = $options['audience'];
			$this->logout_html = $options['logout_html'];
		}

		public function Init() {
			if (is_admin()) {
				// Action link in the plugins page
				add_filter('plugin_action_links', 
						array(&$this, 'Plugin_action_links_filter'), 10, 2);

				add_action('admin_menu', 
						array(&$this, 'Admin_menu_action'));

				if ($this->browserid_only_auth) {
					// XXX this could equally go in browserid-registration
					add_action('admin_action_createuser',
							array(&$this, 'Admin_action_createuser'));
				}
			}

			// top toolbar logout button override
			add_action('admin_bar_menu', 
					array(&$this, 'Admin_toolbar_action'), 999);
		}

		// Add a "Settings" link to the plugin list page.
		public function Plugin_action_links_filter($links, $file) {
			static $this_plugin;

			if (!$this_plugin) {
				$this_plugin = plugin_basename(__FILE__);
			}

			if ($file == $this_plugin) {
				// The "page" query string value must be equal to the slug
				// of the Settings admin page we defined earlier, which in
				// this case equals "myplugin-settings".
				$settings_link = '<a href="'
					. get_bloginfo('wpurl')
					. '/wp-admin/admin.php?page=' . __FILE__ . '">'
					. __('Settings', c_bid_text_domain) . '</a>';
				array_unshift($links, $settings_link);
			}

			return $links;
		}

		// Register options page
		public function Admin_menu_action() {
			if (function_exists('add_options_page'))
				add_options_page(
					__('Mozilla Persona', c_bid_text_domain) . ' ' . __('Administration', c_bid_text_domain),
					__('Mozilla Persona', c_bid_text_domain),
					'manage_options',
					__FILE__,
					array(&$this, 'Render_admin_page'));
		}


		// set a fake password when creating a password for a user.
		// only called if "BrowserID Only" auth is set.
		public function Admin_action_createuser() {
			if (! (isset( $_POST['pass1']) && isset( $_POST['pass2']))) {
				$user_pass = wp_generate_password( 12, false);
				$_POST['pass1'] = $user_pass;
				$_POST['pass2'] = $user_pass;
			}
		}

		// Override logout on site menu
		public function Admin_toolbar_action($wp_toolbar) {
			// If the user is signed in via Persona, replace their toolbar logout
			// with a logout that will work with Persona.
			if ( $this->logged_in_user ) {
				$wp_toolbar->remove_node('logout');
				$wp_toolbar->add_node(array(
					'id' => 'logout',
					'title' => $this->logout_html,
					'parent' => 'user-actions',
					'href' => '#',
					'meta' => array(
						'class' => 'js-persona__logout'
					)
				));
			}
		}

		// Render options page
		public function Render_admin_page() {
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
			if ($this->is_debug) {
				// XXX consider moving a lot of this to browserid-options.
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

				echo '<p><strong>PHP audience</strong>: ' . htmlentities($this->audience) . '</p>';
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
	}
}
?>
