/*
 * NCK code generator for the Alcatel LINKHUB HH71VM.
 *
 * Verified on the HH71VM only. Other devices using the same algorithm may work, but
 * none have been verified and using it on them is not recommended.
 *
 * Everything here runs in the visitor's browser. No IMEI, code or other input ever
 * leaves the page: there is no network request in this file, by design.
 *
 * The calculation depends on nothing but the IMEI and the facility index:
 *
 *   1. BCD-pack the 15 IMEI digits, one leading '0' first, two digits per byte -> 8 bytes.
 *   2. Build a 32-byte message: BCD || tag1 00 00 00 || BCD || tag2 00 00 00 || BCD
 *   3. digest = SHA-1(message), plain and unkeyed.
 *   4. Fold each of the first 16 digest bytes to one decimal digit:
 *        digit[k] = ((digest[k] >> 4) XOR (digest[k] & 0x0F)) mod 10
 *   5. Those sixteen digits are the code. The vendor tool displays them split -- ten,
 *      then six in parentheses as a "control value" -- but the split is a display
 *      convention, not a boundary in the maths. Some devices accept the 10-digit code
 *      and some the full 16 digits, so both forms are surfaced.
 */
(function (root) {
  'use strict';

  /* ------------------------------------------------------------------ *
   * SHA-1                                                              *
   * ------------------------------------------------------------------ *
   * Implemented here rather than via crypto.subtle so the page works
   * synchronously and in any context, including a local file:// copy.
   */
  function sha1(msg) {
    var len = msg.length;
    var blocks = Math.floor((len + 8) / 64) + 1;
    var total = blocks * 64;
    var buf = new Uint8Array(total);
    buf.set(msg);
    buf[len] = 0x80;

    // Message length in bits, big-endian, in the last eight bytes.
    var bits = len * 8;
    for (var p = total - 1; p >= total - 8; p--) {
      buf[p] = bits % 256;
      bits = Math.floor(bits / 256);
    }

    var h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe,
        h3 = 0x10325476, h4 = 0xc3d2e1f0;
    var w = new Int32Array(80);
    var i, f, k, t, v;

    for (var off = 0; off < total; off += 64) {
      for (i = 0; i < 16; i++) {
        var j = off + i * 4;
        w[i] = (buf[j] << 24) | (buf[j + 1] << 16) | (buf[j + 2] << 8) | buf[j + 3];
      }
      for (i = 16; i < 80; i++) {
        v = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
        w[i] = (v << 1) | (v >>> 31);
      }

      var a = h0, b = h1, c = h2, d = h3, e = h4;
      for (i = 0; i < 80; i++) {
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
        else { f = b ^ c ^ d; k = 0xca62c1d6; }
        t = ((((a << 5) | (a >>> 27)) + f + e + k + w[i]) | 0);
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;
      }
      h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0;
      h3 = (h3 + d) | 0; h4 = (h4 + e) | 0;
    }

    var out = new Uint8Array(20);
    [h0, h1, h2, h3, h4].forEach(function (h, n) {
      out[n * 4] = (h >>> 24) & 0xff;
      out[n * 4 + 1] = (h >>> 16) & 0xff;
      out[n * 4 + 2] = (h >>> 8) & 0xff;
      out[n * 4 + 3] = h & 0xff;
    });
    return out;
  }

  /* ------------------------------------------------------------------ *
   * The facility table                                                 *
   * ------------------------------------------------------------------ *
   * Only the two tag bytes differ between facilities; the rest of the
   * 32-byte message is identical. "Other" is the label the vendor tool
   * itself uses. The seventh entry produces a well-formed pair that the
   * vendor GUI never displays, and its facility is unidentified.
   */
  var FACILITIES = [
    { key: 'NCK', name: 'NCK', label: 'Network personalisation', tag1: 0xc0, tag2: 0xcd, primary: true },
    { key: 'NSCK', name: 'NSCK', label: 'Network subset personalisation', tag1: 0x52, tag2: 0xc7 },
    { key: 'SPCK', name: 'SPCK', label: 'Service provider personalisation', tag1: 0x80, tag2: 0x44 },
    { key: 'SIM', name: 'SIM', label: 'SIM / USIM personalisation', tag1: 0xfd, tag2: 0xbe },
    { key: 'C', name: 'C', label: 'Corporate personalisation', tag1: 0x43, tag2: 0x7b },
    { key: 'Other', name: 'Other', label: 'Sixth facility, as labelled by the vendor tool', tag1: 0x6d, tag2: 0x38 },
    { key: 'T6', name: 'T6', label: 'Seventh facility, never shown by the vendor GUI', tag1: 0x90, tag2: 0x90 }
  ];

  /* Keep only the digits, so pasted IMEIs with spaces or dashes work. */
  function digitsOf(value) {
    return String(value == null ? '' : value).replace(/\D+/g, '');
  }

  function bcdPack(digits) {
    var hex = '0' + digits; // 16 nibbles -> 8 bytes
    var out = new Uint8Array(8);
    for (var i = 0; i < 8; i++) {
      out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
  }

  function hex(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) {
      s += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return s;
  }

  /* Returns [{ key, name, label, code, control, primary }, ...] for a 15-digit IMEI. */
  function generate(imei) {
    var digits = digitsOf(imei);
    if (digits.length !== 15) {
      throw new RangeError('IMEI must be 15 digits, got ' + digits.length);
    }
    var bcd = bcdPack(digits);

    return FACILITIES.map(function (facility) {
      var msg = new Uint8Array(32);
      msg.set(bcd, 0);
      msg[8] = facility.tag1;
      msg.set(bcd, 12);
      msg[20] = facility.tag2;
      msg.set(bcd, 24);

      var digest = sha1(msg);
      var s = '';
      for (var i = 0; i < 16; i++) {
        s += String((((digest[i] >> 4) ^ (digest[i] & 0x0f)) % 10));
      }
      return {
        key: facility.key,
        name: facility.name,
        label: facility.label,
        full: s,                 // all sixteen folded digits
        code: s.slice(0, 10),    // what the vendor tool shows as "the code"
        control: s.slice(10),    // what it prints in parentheses
        primary: facility.primary === true
      };
    });
  }

  root.NCK = {
    sha1: sha1,
    hex: hex,
    generate: generate,
    digitsOf: digitsOf,
    FACILITIES: FACILITIES
  };

  /* ------------------------------------------------------------------ *
   * Page wiring                                                        *
   * ------------------------------------------------------------------ */
  if (typeof document === 'undefined') return;

  var form = document.getElementById('nck-form');
  if (!form) return;

  var input = document.getElementById('imei');
  var counter = document.getElementById('imei-counter');
  var error = document.getElementById('imei-error');
  var results = document.getElementById('nck-results');
  var primaryFull = document.getElementById('nck-primary-full');
  var primaryFullCopy = document.getElementById('nck-copy-full');
  var primaryCode = document.getElementById('nck-primary-code');
  var primaryControl = document.getElementById('nck-primary-control');
  var primaryCopy = document.getElementById('nck-primary-copy');
  var echo = document.getElementById('nck-echo');
  var tbody = document.getElementById('nck-tbody');
  var status = document.getElementById('nck-status');
  var resetButton = document.getElementById('nck-reset');

  var copyTimers = new WeakMap();

  function announce(message) {
    if (status) status.textContent = message;
  }

  function setError(message) {
    if (!error) return;
    error.textContent = message || '';
    error.hidden = !message;
    input.setAttribute('aria-invalid', message ? 'true' : 'false');
  }

  function updateCounter() {
    var n = digitsOf(input.value).length;
    if (counter) {
      counter.textContent = n + ' / 15';
      counter.dataset.state = n === 15 ? 'ready' : (n > 15 ? 'over' : 'partial');
    }
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      try {
        var scratch = document.createElement('textarea');
        scratch.value = text;
        scratch.setAttribute('readonly', '');
        scratch.style.position = 'fixed';
        scratch.style.top = '-1000px';
        scratch.style.opacity = '0';
        document.body.appendChild(scratch);
        scratch.select();
        var ok = document.execCommand('copy');
        document.body.removeChild(scratch);
        ok ? resolve() : reject(new Error('copy rejected'));
      } catch (err) {
        reject(err);
      }
    });
  }

  function wireCopy(button, getText, what) {
    button.addEventListener('click', function () {
      var text = getText();
      copyText(text).then(function () {
        var previous = button.dataset.idleLabel || button.textContent;
        button.dataset.idleLabel = previous;
        button.textContent = 'Copied';
        button.classList.add('is-copied');
        announce(what + ' copied to the clipboard.');
        clearTimeout(copyTimers.get(button));
        copyTimers.set(button, setTimeout(function () {
          button.textContent = button.dataset.idleLabel;
          button.classList.remove('is-copied');
        }, 1600));
      }).catch(function () {
        announce('Could not reach the clipboard. Select the code and copy it manually.');
      });
    });
  }

  function render(digits) {
    var rows = generate(digits);
    var primary = rows[0];

    primaryFull.textContent = primary.full;
    primaryCode.textContent = primary.code;
    primaryControl.textContent = primary.control;
    echo.textContent = digits;

    tbody.textContent = '';
    rows.forEach(function (row) {
      var tr = document.createElement('tr');
      if (row.primary) tr.className = 'is-primary';

      var facility = document.createElement('th');
      facility.scope = 'row';
      facility.setAttribute('data-label', 'Facility');
      var strong = document.createElement('span');
      strong.className = 'facility-name';
      strong.textContent = row.name;
      var small = document.createElement('small');
      small.className = 'facility-label';
      small.textContent = row.label;
      facility.appendChild(strong);
      facility.appendChild(small);

      // The flex box lives inside the cell, not on it: a display:flex <td> drops
      // out of table layout and its row borders stop lining up.
      function codeCell(label, value, describe) {
        var cell = document.createElement('td');
        cell.setAttribute('data-label', label);
        var wrap = document.createElement('div');
        wrap.className = 'code-cell';
        var code = document.createElement('code');
        code.className = 'code-value';
        code.textContent = value;
        var copy = document.createElement('button');
        copy.type = 'button';
        copy.className = 'copy-button';
        copy.textContent = 'Copy';
        copy.setAttribute('aria-label', 'Copy the ' + row.name + ' ' + describe);
        wireCopy(copy, function () { return value; }, row.name + ' ' + describe);
        wrap.appendChild(code);
        wrap.appendChild(copy);
        cell.appendChild(wrap);
        return cell;
      }

      tr.appendChild(facility);
      tr.appendChild(codeCell('Full code · 16 digits', row.full, 'full code'));
      tr.appendChild(codeCell('Short code · 10 digits', row.code, 'short code'));
      tbody.appendChild(tr);
    });

    results.hidden = false;
    announce('Codes generated. The full 16-digit NCK is '
      + primary.full.split('').join(' ') + '.');
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    var digits = digitsOf(input.value);

    if (!digits) {
      setError('Enter the 15-digit IMEI of the modem.');
      input.focus();
      return;
    }
    if (digits.length !== 15) {
      setError('An IMEI is 15 digits; this one has ' + digits.length + '.');
      input.focus();
      return;
    }

    setError('');
    input.value = digits;
    updateCounter();
    render(digits);
  });

  input.addEventListener('input', function () {
    updateCounter();
    if (!error.hidden) setError('');
  });

  if (resetButton) {
    resetButton.addEventListener('click', function () {
      input.value = '';
      setError('');
      updateCounter();
      results.hidden = true;
      tbody.textContent = '';
      announce('Cleared.');
      input.focus();
    });
  }

  if (primaryFullCopy) {
    wireCopy(primaryFullCopy, function () { return primaryFull.textContent; }, 'Full 16-digit NCK');
  }

  if (primaryCopy) {
    wireCopy(primaryCopy, function () { return primaryCode.textContent; }, 'Short 10-digit NCK');
  }

  updateCounter();
})(typeof window !== 'undefined' ? window : globalThis);
