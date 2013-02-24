/*jshint browser: true*/
/*global browserid_common: true, alert: true*/
(function() {
  "use strict";

  var login_type, post_id;

  navigator.id.watch({
    loggedInUser: browserid_common.logged_in_user || null,
    onlogin: function(assertion) {
      if (assertion) {
        if(!login_type || login_type === "login") {
          var rememberme = document.getElementById('rememberme');
          if (rememberme !== null)
            rememberme = rememberme.checked;

          var form = document.createElement('form');
          form.setAttribute('style', 'display: none;');
          form.method = 'POST';
          form.action = browserid_common.browserid_siteurl;

          var fields =
            [{name: 'browserid_assertion', value: assertion},
            {name: 'rememberme', value: rememberme}];

          if (browserid_common.browserid_redirect !== null)
            fields.push({name: 'redirect_to', value: browserid_common.browserid_redirect});

          for (var i = 0; i < fields.length; i++) {
            var field = document.createElement('input');
            field.type = 'hidden';
            field.name = fields[i].name;
            field.value = fields[i].value;
            form.appendChild(field);
          }

          document.body.appendChild(form).submit();
        }
        else if(login_type === "comment") {
          var form = jQuery('#browserid_' + post_id).closest('form');
          form.append('<input type="hidden" name="browserid_comment" value="' + post_id + '" />');
          form.append('<input type="hidden" name="browserid_assertion" value="' + assertion + '" />');
          form.find('[type=submit]').click();
        }

      }
      else
        alert(browserid_common.browserid_failed);
    },
    onlogout: function() {
      // There is a bug in Persona with Chrome. When a user signs in, the onlogout callback
      // is first fired. Check if a user is actually signed in before redirecting to the 
      // logout URL
      if (browserid_common.logged_in_user) {
        document.location = browserid_common.wp_logout_url;
      }
    }
  });

  // If there was an error signing in, prevent an endless loop.
  if (browserid_common.browserid_error) {
	navigator.id.logout();
  }

  function browserid_authenticate(type, postid) {
    login_type = type;
    post_id = postid;

    navigator.id.request({
      siteName: browserid_common.browserid_sitename || '',
      siteLogo: browserid_common.browserid_sitelogo || ''
    });

    return false;
  }

  window.browserid_login = function() {
    return browserid_authenticate("login");
  };

  window.browserid_comment = function(postid) {
    return browserid_authenticate("comment", postid);
  };

  window.browserid_logout = function() {
    // log user out from browserid.
    navigator.id.logout();

    return false;
  };

}());
