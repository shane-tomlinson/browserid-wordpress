/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
(function() {
  "use strict";
  var $ = jQuery;

	// add color picker to the background setting
	$('.js-persona__color-picker').wpColorPicker();

  // Add a filepicker where it is needed
  var mediaUploaderFrames = {};
  $('.js-persona__file-picker').click(function(event) {
    event.preventDefault();

    var target = $(event.target);
    var id = target.attr('for');
    var mediaUploaderFrame = mediaUploaderFrames[id];
    if (mediaUploaderFrame) {
      return mediaUploaderFrame.open();
    }

    var mediaUploaderConfig = {
      className: 'media-frame js-persona__media-frame',
      frame: 'select',
      multiple: false,
      title: target.attr('data-title') || '',
      input: $('#' + target.attr('for'))
    };

    var mediaType = target.attr('data-type');
    if (mediaType) {
      mediaUploaderConfig.library = {
        type: mediaType
      };
    }

    mediaUploaderFrame = mediaUploaderFrames[id] =
            wp.media(mediaUploaderConfig);

    mediaUploaderFrame.on('select', function() {
      var attachment =
          mediaUploaderFrame.state().get('selection').first().toJSON();

      mediaUplaoderConfig.input.val(attachment.url);
    });

    mediaUploaderFrame.open();
  });
}());

