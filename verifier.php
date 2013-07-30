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

if (!class_exists('MozillaPersonaVerifier')) {
	class MozillaPersonaVerifier {
	private $audience;
	private $vserver;

	public function __construct($audience, $vserver) {
		$this->audience = $audience;
		$this->vserver = $vserver;
	}

	// Post the assertion to the verifier. If the assertion does not
	// verify, an error message will be displayed and no more processing
	// will occur
	public function Verify($assertion) {
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
				'audience' => $this->audience
			),
			'cookies' => array(),
			'sslverify' => true
		);

		// Verify assertion
		$response = wp_remote_post($this->vserver, $args);

		if (is_wp_error($response)) {
			return $response;
		}

		return $this->Check_response($response);
	}

	function Check_response($response) {
		$result = json_decode($response['body'], true);

		if (empty($result) || empty($result['status'])) {
			return new WP_Error('verification_response_invalid', 
					__('Verification response invalid', c_bid_text_domain));
		}
		else if ($result['status'] != 'okay') {
			$message = __('Verification failed', c_bid_text_domain);
			if (isset($result['reason']))
				$message .= ': ' . __($result['reason'], c_bid_text_domain);

			return new WP_Error('verification_failed', $message);

		}

		// Success!
		return $result;

	}
  }
}
?>
