/**
 * 2FA Guardian — Login Page JS
 * Handles method switching, code submission, WebAuthn, and email resend.
 */
/* global guardianData, jQuery */

(function($) {
  'use strict';

  // -------------------------------------------------------------------
  // State
  // -------------------------------------------------------------------
  let currentMethod = ($('#guardian-verify-btn').data('method') || 'totp');

  // -------------------------------------------------------------------
  // Method tab switching
  // -------------------------------------------------------------------
  $(document).on('click', '.guardian-method-tab', function() {
    const method = $(this).data('method');
    currentMethod = method;

    $('.guardian-method-tab').removeClass('is-active').attr('aria-selected', 'false');
    $(this).addClass('is-active').attr('aria-selected', 'true');

    $('.guardian-panel').removeClass('is-active');
    $('#panel-' + method).addClass('is-active');

    $('#guardian-verify-btn').data('method', method);
    clearStatus();

    // Auto-trigger WebAuthn when tab is selected
    if (method === 'webauthn') {
      setTimeout(triggerWebAuthn, 400);
    }
  });

  // -------------------------------------------------------------------
  // Verify button
  // -------------------------------------------------------------------
  $('#guardian-verify-btn').on('click', function() {
    const method = $(this).data('method') || currentMethod;

    if (method === 'webauthn') {
      triggerWebAuthn();
      return;
    }

    const code = getCodeForMethod(method);
    if (!code) {
      showStatus('Please enter the verification code.', 'error');
      return;
    }

    submitVerification(method, code);
  });

  // Allow Enter key
  $(document).on('keydown', '.guardian-code-input', function(e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      $('#guardian-verify-btn').trigger('click');
    }
  });

  // Auto-format code input
  $(document).on('input', '#totp-code, #email-code', function() {
    let val = this.value.replace(/\D/g, '').slice(0, 6);
    this.value = val;
  });

  $(document).on('input', '#backup-code', function() {
    let val = this.value.replace(/[^A-Za-z0-9\-]/g, '').toUpperCase();
    this.value = val;
  });

  // -------------------------------------------------------------------
  // Get code value for current method
  // -------------------------------------------------------------------
  function getCodeForMethod(method) {
    switch (method) {
      case 'totp':   return $('#totp-code').val().replace(/\s/g, '');
      case 'email':  return $('#email-code').val().replace(/\s/g, '');
      case 'backup': return $('#backup-code').val().replace(/\s/g, '');
      default:       return '';
    }
  }

  // -------------------------------------------------------------------
  // Submit 2FA verification
  // -------------------------------------------------------------------
  function submitVerification(method, code, extra) {
    const $btn = $('#guardian-verify-btn');
    $btn.addClass('is-loading').prop('disabled', true);
    clearStatus();

    $.post(guardianData.ajax_url, $.extend({
      action:  'guardian_verify_2fa',
      nonce:   guardianData.nonce,
      method:  method,
      code:    code,
      trust_device: $('#trust-device').is(':checked') ? 1 : 0,
      remember_me:  0,
    }, extra || {}))
    .done(function(res) {
      if (res.success) {
        showStatus('Verified! Redirecting…', 'success');
        setTimeout(function() {
          window.location.href = res.data.redirect || '/wp-admin/';
        }, 800);
      } else {
        showStatus(res.data.message || 'Verification failed. Please try again.', 'error');
        $btn.removeClass('is-loading').prop('disabled', false);
      }
    })
    .fail(function() {
      showStatus('Network error. Please try again.', 'error');
      $btn.removeClass('is-loading').prop('disabled', false);
    });
  }

  // -------------------------------------------------------------------
  // Email OTP — resend
  // -------------------------------------------------------------------
  let resendCooldown = false;
  $('#resend-email-btn').on('click', function() {
    if (resendCooldown) {
      showStatus('Please wait before requesting a new code.', 'error');
      return;
    }

    const $btn = $(this);
    $btn.prop('disabled', true).text('Sending…');
    clearStatus();

    $.post(guardianData.ajax_url, {
      action: 'guardian_resend_email_otp',
      nonce:  guardianData.nonce,
    })
    .done(function(res) {
      if (res.success) {
        showStatus(res.data.message, 'success');
        resendCooldown = true;
        let secs = 60;
        const iv = setInterval(function() {
          secs--;
          $btn.text('Resend code (' + secs + 's)');
          if (secs <= 0) {
            clearInterval(iv);
            $btn.prop('disabled', false).text('Resend code');
            resendCooldown = false;
          }
        }, 1000);
      } else {
        showStatus(res.data.message || 'Failed to resend.', 'error');
        $btn.prop('disabled', false).text('Resend code');
      }
    })
    .fail(function() {
      showStatus('Network error.', 'error');
      $btn.prop('disabled', false).text('Resend code');
    });
  });

  // -------------------------------------------------------------------
  // WebAuthn
  // -------------------------------------------------------------------
  $('#webauthn-trigger-btn').on('click', function() {
    triggerWebAuthn();
  });

  async function triggerWebAuthn() {
    if (!window.PublicKeyCredential) {
      showStatus('Your browser does not support WebAuthn security keys.', 'error');
      return;
    }

    setWebAuthnStatus('Requesting challenge from server…', false);

    try {
      // Step 1: Get challenge from server
      const challengeRes = await $.post(guardianData.ajax_url, {
        action: 'guardian_webauthn_challenge',
        nonce:  guardianData.nonce,
      });

      if (!challengeRes.success) {
        throw new Error(challengeRes.data?.message || 'Failed to get challenge.');
      }

      const opts = challengeRes.data;

      // Decode base64url fields
      const publicKey = {
        challenge:        base64urlToUint8(opts.challenge),
        rpId:             opts.rpId,
        timeout:          opts.timeout,
        userVerification: opts.userVerification,
        allowCredentials: (opts.allowCredentials || []).map(c => ({
          type:       c.type,
          id:         base64urlToUint8(c.id),
          transports: c.transports || [],
        })),
      };

      setWebAuthnStatus('Tap your security key or use biometrics…', true);

      // Step 2: Get assertion from authenticator
      const credential = await navigator.credentials.get({ publicKey });

      setWebAuthnStatus('Verifying with server…', false);

      // Step 3: Send assertion to server
      const credData = {
        id:   credential.id,
        rawId: uint8ToBase64url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON:    uint8ToBase64url(credential.response.clientDataJSON),
          authenticatorData: uint8ToBase64url(credential.response.authenticatorData),
          signature:         uint8ToBase64url(credential.response.signature),
          userHandle:        credential.response.userHandle ? uint8ToBase64url(credential.response.userHandle) : null,
        },
      };

      const authRes = await $.post(guardianData.ajax_url, {
        action:     'guardian_webauthn_authenticate',
        nonce:      guardianData.nonce,
        credential: JSON.stringify(credData),
      });

      if (!authRes.success) {
        throw new Error(authRes.data?.message || 'Authentication failed.');
      }

      // Step 4: Complete login using token
      submitVerification('webauthn', 'webauthn_verified:' + authRes.data.token);

    } catch (err) {
      if (err.name === 'NotAllowedError') {
        setWebAuthnStatus('Request was cancelled or timed out. Click to try again.', false);
      } else {
        setWebAuthnStatus('Error: ' + (err.message || 'WebAuthn failed.'), false);
      }
    }
  }

  function setWebAuthnStatus(msg, isActive) {
    $('#webauthn-status').text(msg);
    if (isActive) {
      $('#key-icon-anim').css('animation', 'key-tap 0.8s ease-in-out infinite');
    } else {
      $('#key-icon-anim').css('animation', 'none');
    }
  }

  // -------------------------------------------------------------------
  // Status helper
  // -------------------------------------------------------------------
  function showStatus(msg, type) {
    $('#guardian-status')
      .removeClass('is-error is-success is-info')
      .addClass('is-' + type)
      .text(msg);
  }

  function clearStatus() {
    $('#guardian-status').removeClass('is-error is-success is-info').text('');
  }

  // -------------------------------------------------------------------
  // Base64url helpers for WebAuthn
  // -------------------------------------------------------------------
  function base64urlToUint8(str) {
    const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(b64);
    return Uint8Array.from(raw, c => c.charCodeAt(0));
  }

  function uint8ToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    bytes.forEach(b => { str += String.fromCharCode(b); });
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  // -------------------------------------------------------------------
  // Auto-focus first input
  // -------------------------------------------------------------------
  $(function() {
    if (currentMethod === 'webauthn') {
      setTimeout(triggerWebAuthn, 600);
    } else {
      $('.guardian-panel.is-active .guardian-code-input').first().focus();
    }
  });

})(jQuery);
