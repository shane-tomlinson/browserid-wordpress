/*jshint browser: true*/
/*global browserid_common: true, alert: true*/
(function() {
  "use strict";

  var login_type, post_id;

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

  if (browserid_common.logout || browserid_common.error) {
    navigator.id.logout();
  }

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
          form.action = browserid_common.siteurl;

          var fields = [
            {name: 'browserid_assertion', value: assertion},
            {name: 'rememberme', value: rememberme}
          ];

          if (browserid_common.login_redirect !== null)
            fields.push({name: 'redirect_to', value: browserid_common.login_redirect});

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
          var form = jQuery('#browserid_' + post_id).closest('form')[0];
          var fields = [
            {name: 'browserid_comment', value: post_id},
            {name: 'browserid_assertion', value: assertion}
          ];
          for (var i = 0; i < fields.length; i++) {
            var field = document.createElement('input');
            field.type = 'hidden';
            field.name = fields[i].name;
            field.value = fields[i].value;
            form.appendChild(field);
          }
          form.submit();
        }

      }
      else
        alert(browserid_common.failed);
    },
    onlogout: function() {
      // There is a bug in Persona with Chrome. When a user signs in, the
      // onlogout callback is first fired. Check if a user is actually
      // signed in before redirecting to the logout URL.
      if (browserid_common.logged_in_user) {
        document.location = browserid_common.logout_redirect;
      }
    }
  });

  function browserid_authenticate(type, postid) {
    login_type = type;
    post_id = postid;

    navigator.id.request({
      siteName: browserid_common.sitename || '',
      siteLogo: browserid_common.sitelogo || ''
    });

    return false;
  }

}());
