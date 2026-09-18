/* Xproxy browser challenge: find counter such that SHA-256(nonce ":" counter)
   has the required number of leading zero bits, then post it back. */
(function () {
  "use strict";
  var K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  var W = new Int32Array(64);

  // sha256 of an ASCII string; returns the first 4 bytes as a 32-bit int
  // and the full digest is not needed: difficulty is at most 24 bits.
  function sha256Prefix(str) {
    var n = str.length, bytes = new Uint8Array(((n + 9 + 63) >> 6) << 6);
    for (var i = 0; i < n; i++) bytes[i] = str.charCodeAt(i) & 0xff;
    bytes[n] = 0x80;
    var bits = n * 8, L = bytes.length;
    bytes[L - 4] = (bits >>> 24) & 0xff; bytes[L - 3] = (bits >>> 16) & 0xff;
    bytes[L - 2] = (bits >>> 8) & 0xff; bytes[L - 1] = bits & 0xff;
    var h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    for (var off = 0; off < L; off += 64) {
      for (var t = 0; t < 16; t++) {
        var j = off + t * 4;
        W[t] = (bytes[j] << 24) | (bytes[j+1] << 16) | (bytes[j+2] << 8) | bytes[j+3];
      }
      for (t = 16; t < 64; t++) {
        var w15 = W[t-15], w2 = W[t-2];
        var s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
        var s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
        W[t] = (W[t-16] + s0 + W[t-7] + s1) | 0;
      }
      var a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
      for (t = 0; t < 64; t++) {
        var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K[t] + W[t]) | 0;
        var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        var mj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + mj) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h0=(h0+a)|0;h1=(h1+b)|0;h2=(h2+c)|0;h3=(h3+d)|0;h4=(h4+e)|0;h5=(h5+f)|0;h6=(h6+g)|0;h7=(h7+h)|0;
    }
    return h0 >>> 0;
  }

  function leadingZeros32(x) {
    if (x === 0) return 32;
    var n = 0;
    while ((x & 0x80000000) === 0) { n++; x = (x << 1) >>> 0; }
    return n;
  }

  var body = document.body;
  var nonce = body.getAttribute("data-nonce");
  var difficulty = parseInt(body.getAttribute("data-difficulty"), 10) || 16;
  var ret = body.getAttribute("data-return") || "/";
  var verify = body.getAttribute("data-verify");
  var bar = document.getElementById("bar");
  var msg = document.getElementById("msg");
  var expected = Math.pow(2, difficulty);
  var counter = 0;

  function submit(found) {
    var form = document.createElement("form");
    form.method = "POST";
    form.action = verify;
    var add = function (k, v) { var i = document.createElement("input"); i.type = "hidden"; i.name = k; i.value = v; form.appendChild(i); };
    add("nonce", nonce); add("counter", String(found)); add("r", ret);
    document.body.appendChild(form);
    form.submit();
  }

  function work() {
    var deadline = Date.now() + 40;
    while (Date.now() < deadline) {
      for (var i = 0; i < 256; i++) {
        if (leadingZeros32(sha256Prefix(nonce + ":" + counter)) >= difficulty) { bar.style.width = "100%"; submit(counter); return; }
        counter++;
      }
    }
    bar.style.width = Math.min(95, 100 * (1 - Math.exp(-counter / expected))) + "%";
    setTimeout(work, 0);
  }

  if (!nonce || !verify) { msg.textContent = "Challenge unavailable."; return; }
  setTimeout(work, 0);
})();
