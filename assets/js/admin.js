/**
 * 2FA Guardian — Admin JS
 * Handles: TOTP setup, Email OTP, WebAuthn registration, Backup Codes,
 * settings save, dashboard actions.
 */
/* global guardianAdmin, jQuery, $ */

(function($) {
  'use strict';

  const REST  = guardianAdmin.rest_url;
  const NONCE = guardianAdmin.nonce;
  const AJAX  = guardianAdmin.ajax_url;
  const i18n  = guardianAdmin.i18n || {};

  // -------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------
  function apiPost(path, data) {
    return $.ajax({
      url:    REST + path,
      method: 'POST',
      beforeSend: xhr => xhr.setRequestHeader('X-WP-Nonce', NONCE),
      data,
    });
  }

  function ajaxPost(action, data) {
    return $.post(AJAX, $.extend({ action, nonce: NONCE }, data));
  }

  function base64urlToUint8(str) {
    const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(b64);
    return Uint8Array.from(raw, c => c.charCodeAt(0));
  }

  function uint8ToBase64url(buf) {
    const bytes = new Uint8Array(buf);
    let str = '';
    bytes.forEach(b => { str += String.fromCharCode(b); });
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  function showAdminNotice(msg, type) {
    const $n = $('#guardian-settings-notice');
    $n.removeClass('notice-success notice-error notice-info')
      .addClass('notice-' + (type || 'success'))
      .empty()
      .append($('<p>').text(msg))
      .show();
    setTimeout(() => $n.fadeOut(), 4000);
  }

  function completeSetupFlow(message) {
    if (guardianAdmin.setup_required) {
      if (message) {
        $('#key-registration-status').text(message).css('color', 'green');
      }
      window.setTimeout(() => {
        window.location.href = guardianAdmin.setup_redirect || '/wp-admin/';
      }, 900);
      return true;
    }

    return false;
  }

  // -------------------------------------------------------------------
  // Dashboard — Unblock IP
  // -------------------------------------------------------------------
  $(document).on('click', '.guardian-unblock-btn', function() {
    const $btn = $(this);
    const ip   = $btn.data('ip');
    $btn.prop('disabled', true).text('Unblocking…');

    ajaxPost('guardian_unblock_ip', { ip })
      .done(res => {
        if (res.success) {
          $btn.closest('li').fadeOut(300, function() { $(this).remove(); });
        } else {
          $btn.prop('disabled', false).text('Unblock');
        }
      });
  });

  // Dashboard — Purge logs
  $(document).on('click', '#guardian-purge-logs', function() {
    if (!confirm('Purge ALL security logs? This cannot be undone.')) return;
    const $btn = $(this);
    $btn.prop('disabled', true);
    ajaxPost('guardian_purge_logs').done(() => {
      $btn.text('✅ Purged').prop('disabled', false);
      $('tbody').html('<tr><td colspan="4" style="text-align:center;color:#999;">No activity yet.</td></tr>');
    });
  });

  // -------------------------------------------------------------------
  // Settings form save
  // -------------------------------------------------------------------
  $('#guardian-settings-form').on('submit', function(e) {
    e.preventDefault();
    const $btn  = $(this).find('.guardian-save-btn');
    const data  = {};
    const arr   = $(this).serializeArray();

    // Reset arrays
    data.enforce_roles     = [];
    data.allowed_methods   = [];

    arr.forEach(item => {
      if (item.name === 'enforce_roles[]')     { data.enforce_roles.push(item.value); return; }
      if (item.name === 'allowed_methods[]')   { data.allowed_methods.push(item.value); return; }
      const key = item.name.replace('[]', '');
      data[key] = item.value;
    });

    $btn.prop('disabled', true).text('Saving…');

    ajaxPost('guardian_save_settings', data)
      .done(res => {
        if (res.success) {
          showAdminNotice(res.data.message, 'success');
        } else {
          showAdminNotice('Save failed.', 'error');
        }
        $btn.prop('disabled', false).text('Save Settings');
      })
      .fail(() => {
        showAdminNotice('Network error.', 'error');
        $btn.prop('disabled', false).text('Save Settings');
      });
  });

  // -------------------------------------------------------------------
  // TOTP Setup
  // -------------------------------------------------------------------
  $('.guardian-setup-totp-btn').on('click', function() {
    const $modal = $('#guardian-totp-modal');
    $modal.show();

    ajaxPost('guardian_totp_setup')
      .done(res => {
        if (res.success) {
          $('#totp-secret-text').text(res.data.secret);
          if (res.data.qr_url) {
            $('#totp-qr-img').attr('src', res.data.qr_url).show();
          } else {
            $('#totp-qr-img').attr('src', '').hide();
          }
        }
      });
  });

  $('#totp-activate-btn').on('click', function() {
    const code = $('#totp-verify-code').val().replace(/\s/g, '');
    if (!code || code.length !== 6) {
      $('#totp-error').text('Enter the 6-digit code from your app.').show();
      return;
    }
    $(this).prop('disabled', true).text('Activating…');

    ajaxPost('guardian_totp_activate', { code })
      .done(res => {
        if (res.success) {
          if (completeSetupFlow(res.data.message || '2FA enabled. Redirecting…')) {
            closeModal('#guardian-totp-modal');
            return;
          }
          closeModal('#guardian-totp-modal');
          location.reload();
        } else {
          $('#totp-error').text(res.data.message || 'Invalid code.').show();
          $('#totp-activate-btn').prop('disabled', false).text('Activate');
        }
      });
  });

  $('#copy-totp-secret').on('click', function() {
    const secret = $('#totp-secret-text').text();
    copyToClipboard(secret, this);
  });

  // TOTP disable
  $(document).on('click', '.guardian-disable-btn[data-action="guardian_totp_disable"]', function() {
    if (!confirm('Remove authenticator app? You will need another 2FA method.')) return;
    ajaxPost('guardian_totp_disable').done(res => {
      if (res.success) location.reload();
    });
  });

  // -------------------------------------------------------------------
  // Email OTP
  // -------------------------------------------------------------------
  $(document).on('click', '.guardian-enable-btn[data-action="guardian_email_otp_activate"]', function() {
    ajaxPost('guardian_email_otp_activate').done(res => {
      if (res.success) {
        if (!completeSetupFlow(res.data.message || '2FA enabled. Redirecting…')) {
          location.reload();
        }
      }
    });
  });

  $(document).on('click', '.guardian-disable-btn[data-action="guardian_email_otp_disable"]', function() {
    if (!confirm('Disable email OTP?')) return;
    ajaxPost('guardian_email_otp_disable').done(res => {
      if (res.success) location.reload();
    });
  });

  // -------------------------------------------------------------------
  // Backup Codes
  // -------------------------------------------------------------------
  $('.guardian-gen-backup-btn').on('click', function() {
    const existing = parseInt($('.guardian-method-card.is-enabled').length, 10);
    if (existing && !confirm('This will invalidate your existing backup codes. Continue?')) return;

    ajaxPost('guardian_gen_backup').done(res => {
      if (res.success && res.data.codes) {
        const $grid = $('#backup-codes-display').empty();
        res.data.codes.forEach(code => {
          $grid.append($('<code>').text(code));
        });
        $('#guardian-backup-modal').show();
      }
    });
  });

  $('#copy-all-backup-codes').on('click', function() {
    const codes = [];
    $('#backup-codes-display code').each(function() {
      codes.push($(this).text());
    });
    copyToClipboard(codes.join('\n'), this);
  });

  // -------------------------------------------------------------------
  // WebAuthn — Register security key
  // -------------------------------------------------------------------
  $('.guardian-add-key-btn, #guardian-add-key-btn').on('click', function(e) {
    e.preventDefault();
    $('#guardian-keys-modal').show();
    loadKeysList();
  });

  $('.guardian-manage-keys-btn').on('click', function(e) {
    e.preventDefault();
    $('#guardian-keys-modal').show();
    loadKeysList();
  });

  $('#register-key-btn').on('click', async function(e) {
    e.preventDefault();
    if (!window.PublicKeyCredential) {
      $('#key-registration-status').text('❌ Your browser does not support WebAuthn.').css('color', 'red');
      return;
    }

    const keyName = $('#new-key-name').val().trim() || 'Security Key';
    const $btn    = $(this);
    $btn.prop('disabled', true).text('Waiting for key…');
    $('#key-registration-status').text('').css('color', '');

    try {
      // Get creation options
      const optRes = await ajaxPost('guardian_webauthn_get_options');
      if (!optRes.success) throw new Error(optRes.data?.message || 'Failed to get options.');

      const opts    = optRes.data;
      const pubKey  = {
        challenge:                  base64urlToUint8(opts.challenge),
        rp:                         opts.rp,
        user: {
          id:          base64urlToUint8(opts.user.id),
          name:        opts.user.name,
          displayName: opts.user.displayName,
        },
        pubKeyCredParams:            opts.pubKeyCredParams,
        authenticatorSelection:      opts.authenticatorSelection,
        timeout:                     opts.timeout,
        attestation:                 opts.attestation,
        excludeCredentials:          (opts.excludeCredentials || []).map(c => ({
          type: c.type,
          id:   base64urlToUint8(c.id),
        })),
      };

      const credential = await navigator.credentials.create({ publicKey: pubKey });

      const credData = {
        id:   credential.id,
        rawId: uint8ToBase64url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON:    uint8ToBase64url(credential.response.clientDataJSON),
          attestationObject: uint8ToBase64url(credential.response.attestationObject),
        },
      };

      const regRes = await ajaxPost('guardian_webauthn_register', {
        credential: JSON.stringify(credData),
        key_name:   keyName,
      });

      if (!regRes.success) throw new Error(regRes.data?.message || 'Registration failed.');

      $('#key-registration-status').text('✅ ' + (regRes.data?.message || 'Key registered!')).css('color', 'green');
      $('#new-key-name').val('');
      if (completeSetupFlow('✅ ' + (regRes.data?.message || 'Key registered!'))) {
        return;
      }
      loadKeysList();

    } catch (err) {
      const msg = err.name === 'NotAllowedError' ? 'Request cancelled.' : (err.message || 'Failed.');
      $('#key-registration-status').text('❌ ' + msg).css('color', 'red');
    }

    $btn.prop('disabled', false).text('Register Key');
  });

  function loadKeysList() {
    ajaxPost('guardian_webauthn_list_keys').done(res => {
      if (!res.success) return;
      const $list = $('#guardian-keys-list').empty();
      if (!res.data.keys.length) {
        $list.html('<p style="color:#999;font-size:13px;">No security keys registered yet.</p>');
        return;
      }
      res.data.keys.forEach(key => {
        const lastUsed = key.last_used_at ? new Date(key.last_used_at).toLocaleDateString() : 'Never';
        $list.append(`
          <div class="guardian-key-item" data-id="${key.id}">
            <div>
              <div class="guardian-key-item__name">🔑 ${escHtml(key.name)}</div>
              <div class="guardian-key-item__meta">Added ${new Date(key.created_at).toLocaleDateString()} · Last used: ${lastUsed}</div>
            </div>
            <button type="button" class="button guardian-remove-key-btn" data-id="${key.id}">${i18n.confirm_remove ? 'Remove' : 'Remove'}</button>
          </div>
        `);
      });
    });
  }

  $(document).on('click', '.guardian-remove-key-btn', function(e) {
    e.preventDefault();
    if (!confirm(i18n.confirm_remove || 'Remove this security key?')) return;
    const $btn  = $(this);
    const keyId = $btn.data('id');
    ajaxPost('guardian_webauthn_remove_key', { key_id: keyId }).done(res => {
      if (res.success) $btn.closest('.guardian-key-item').fadeOut(200, function() { $(this).remove(); });
    });
  });

  // -------------------------------------------------------------------
  // Trusted Devices
  // -------------------------------------------------------------------
  function loadTrustedDevices() {
    const $list = $('#guardian-trusted-devices-list');
    if (!$list.length) return;

    // Fetch via admin-ajax (simple approach)
    $list.html('Loading…');
    $.post(AJAX, { action: 'guardian_get_trusted_devices', nonce: NONCE, user_id: guardianAdmin.user_id })
      .done(res => {
        if (res.success && res.data.devices.length) {
          let html = '<table style="width:100%;border-collapse:collapse;font-size:13px"><thead><tr><th style="text-align:left;padding:6px 10px;border-bottom:1px solid #eee">Device</th><th style="text-align:left;padding:6px 10px;border-bottom:1px solid #eee">IP</th><th style="text-align:left;padding:6px 10px;border-bottom:1px solid #eee">Expires</th></tr></thead><tbody>';
          res.data.devices.forEach(d => {
            html += `<tr>
              <td style="padding:6px 10px">${escHtml(d.device_name)}</td>
              <td style="padding:6px 10px"><code>${escHtml(d.ip_address || '—')}</code></td>
              <td style="padding:6px 10px">${escHtml(d.expires_at)}</td>
            </tr>`;
          });
          html += '</tbody></table>';
          $list.html(html);
        } else {
          $list.html('<p style="color:#999;font-size:13px">No trusted devices.</p>');
        }
      });
  }

  $('#guardian-revoke-all-devices').on('click', function() {
    if (!confirm('Revoke all trusted devices? You will need to verify 2FA on all devices on next login.')) return;
    $.post(AJAX, { action: 'guardian_revoke_trusted_devices', nonce: NONCE, user_id: guardianAdmin.user_id })
      .done(() => loadTrustedDevices());
  });

  // -------------------------------------------------------------------
  // Admin reset user 2FA
  // -------------------------------------------------------------------
  $(document).on('click', '.guardian-admin-reset-btn', function() {
    const userId = $(this).data('user-id');
    if (!confirm('Reset 2FA for this user? They will need to set it up again.')) return;
    ajaxPost('guardian_admin_reset_user_2fa', { user_id: userId }).done(res => {
      if (res.success) {
        $(this).closest('.guardian-admin-reset-section').html('<p style="color:green">✅ ' + res.data.message + '</p>');
      }
    });
  });

  // -------------------------------------------------------------------
  // Modal close
  // -------------------------------------------------------------------
  $(document).on('click', '.guardian-modal__close, .guardian-modal__backdrop', function() {
    closeModal($(this).closest('.guardian-modal'));
  });
  $(document).on('keydown', function(e) {
    if (e.key === 'Escape') $('.guardian-modal:visible').hide();
  });

  function closeModal(selector) {
    $(selector).hide();
  }

  // -------------------------------------------------------------------
  // Clipboard helper
  // -------------------------------------------------------------------
  function copyToClipboard(text, btn) {
    navigator.clipboard.writeText(text).then(() => {
      const $btn = $(btn);
      const orig = $btn.text();
      $btn.text(i18n.copy_success || 'Copied!');
      setTimeout(() => $btn.text(orig), 2000);
    });
  }

  // -------------------------------------------------------------------
  // Escape HTML helper
  // -------------------------------------------------------------------
  function escHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // -------------------------------------------------------------------
  // Init
  // -------------------------------------------------------------------
  $(function() {
    loadTrustedDevices();
  });

})(jQuery);
