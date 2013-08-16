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


if (!class_exists('MozillaPersonaComments')) {
	class MozillaPersonaComments {
		private $ui = null;
		private $is_comments_enabled = false;
		private $is_bbpress_enabled = false;
		private $button_html = null;

		public function __construct($options) {
			$this->is_comments_enabled = $options['is_comments_enabled'];
			$this->is_bbpress_enabled = $options['is_bbpress_enabled'];
			$this->ui = $options['ui'];
			$this->button_html = $options['button_html'];
		}

		public function Init() {
			if (! $this->is_comments_enabled) return;

			add_filter('comment_form_default_fields', 
					array(&$this, 'Comment_form_action_default_fields_filter'));
			add_action('comment_form', 
					array(&$this, 'Comment_form_action'));
			add_filter('pre_comment_approved', 
					array(&$this, 'Pre_comment_approved_filter'), 20, 2);
		}

		public function Is_comment() {
			if ($this->is_comments_enabled || $this->enabled_for_bbpress) 
				return (isset($_REQUEST['browserid_comment']) ? $_REQUEST['browserid_comment'] : null);

			return null;
		}

		// Process comment
		public function Handle_comment($email) {
			// Initialize
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


		// Get rid of the email field in the comment form
		public function Comment_form_action_default_fields_filter($fields) {
			unset($fields['email']);
			return $fields;
		}

		// Add BrowserID to comment form
		public function Comment_form_action($post_id) {
			if (!is_user_logged_in()) {
				$this->ui->Print_persona_button_html(
						"js-persona__submit-comment", $this->button_html);
			}

			// Display error message
			// XXX can this be taken care of in browserid.php somehow?
			if (isset($_REQUEST['browserid_error'])) {
				$this->ui->Print_persona_error(
						$_REQUEST['browserid_error'], 'persona__error-comment');
			}
		}

		// If Persona-Only auth is enabled, comment must be submitted with an
		// assertion.
		public function Pre_comment_approved_filter($approved, $commentdata) {
			$assertion = $this->ui->Get_assertion();
			if (empty($assertion)) {
				if ( defined('DOING_AJAX') )
					die(__('Comment must be submitted using Persona'));

				wp_die(__('Comment must be submitted using Persona'));
			}
		}
	}

}
