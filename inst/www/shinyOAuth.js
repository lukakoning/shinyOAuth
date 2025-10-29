/* shinyOAuth.js - external client helpers to avoid inline scripts (CSP-friendly)
 * Handlers:
 *  - shinyOAuth:setBrowserToken    {instance, maxAgeMs, sameSite, path, inputId}
 *  - shinyOAuth:clearBrowserToken  {instance, sameSite, path}
 *  - shinyOAuth:redirect           {url}
 *  - shinyOAuth:clearQueryAndFixTitle {titleReplacement, cleanTitle}
 */
(function(){
  'use strict';

  function getCookie(name){
    var m=document.cookie.match('(?:^|; )'+name+'=([^;]*)');
    return m?decodeURIComponent(m[1]):null;
  }

  function isValidHexToken(v, expectedLen){
    if(!v || typeof v !== 'string') return false;
    if(v.length !== expectedLen) return false;
    return (/^[a-f0-9]+$/).test(v);
  }

  // Normalize a cookie path. If base is falsy and defaultToRoot is true,
  // return '/'. Otherwise, derive from current location as a last resort.
  function normPath(p, defaultToRoot){
    try {
      if (!p) p = defaultToRoot ? '/' : (window.location.pathname || '/');
      p = String(p);
      if (p[0] !== '/') p = '/' + p;
      p = p.replace(/[?#].*$/, '') || '/';
      return p;
    } catch(e) { return '/'; }
  }

  function setCookie(name,val,ageMs,sameSite,forceSecure,cookiePath){
    var d=new Date(); d.setTime(d.getTime()+ageMs);
    var parts=[
      name+'='+encodeURIComponent(val),
      'Expires='+d.toUTCString(),
      'Max-Age='+Math.floor(ageMs/1000),
      'Path='+cookiePath,
      'SameSite='+sameSite
    ];
    var isHttps = window.location.protocol==='https:';
    if (isHttps || forceSecure) parts.push('Secure');
    document.cookie = parts.join('; ');
  }

  function randomHex(bytes){
    if (!window.crypto || !window.crypto.getRandomValues) {
      throw new Error('webcrypto_unavailable');
    }
    var a=new Uint8Array(bytes); window.crypto.getRandomValues(a);
    return Array.from(a, function(x){return x.toString(16).padStart(2,'0');}).join('');
  }

  function clearCookiesFor(name, sameSite, cookiePath){
    var isHttps = window.location.protocol==='https:';
    var paths = [];
    // Always try the configured/remembered path
    paths.push(cookiePath);
    // Also try root as a safety net
    if (cookiePath !== '/') paths.push('/');

    paths.forEach(function(p){
      // Clear regular cookie name
      document.cookie = name + '=; Max-Age=0; Path=' + p + '; SameSite=' + sameSite + (isHttps ? '; Secure' : '');
      // Clear host-prefixed variant (used when Path=/ over HTTPS)
      if (isHttps) document.cookie = '__Host-' + name + '=; Max-Age=0; Path=/; SameSite=' + sameSite + '; Secure';
    });
  }

  function ensureShiny(){ return (window.Shiny && Shiny.setInputValue) ? Shiny : null; }

  function handleSetBrowserToken(payload){
    try {
      var sameSite = payload.sameSite || 'Strict';
      // Default to a fixed, known path '/' when none is supplied
      var cfg = (payload.path === undefined || payload.path === null || payload.path === '') ? '/' : String(payload.path);
      var cookiePath = normPath(cfg, /*defaultToRoot*/ true);
      // Honor explicit zero TTLs; only fall back when maxAgeMs is null/undefined
      var ageMs = Number((payload.maxAgeMs ?? 3600000));
      var inst = String(payload.instance || '');
      var isHttps = window.location.protocol==='https:';
      var requireSecure = (sameSite === 'None');
      if (requireSecure && !isHttps) throw new Error('samesite_none_requires_https');
      var useHostPrefix = isHttps && cookiePath === '/';
      var base = useHostPrefix ? '__Host-shinyOAuth_sid' : 'shinyOAuth_sid';
      var name = base + (inst ? ('-' + inst) : '');
      var v = getCookie(name);
      var expectedLen = 128; /* 64 bytes hex-encoded */
      if(!isValidHexToken(v, expectedLen)){ v = randomHex(64); }
      setCookie(name, v, ageMs, sameSite, /*forceSecure*/ requireSecure, cookiePath);
      var shiny = ensureShiny();
      if (shiny) shiny.setInputValue(payload.inputId, v, {priority:'event'});
    } catch(e) {
      var shiny = ensureShiny();
      if (shiny) shiny.setInputValue(payload.errorInputId, String(e && e.message || e), {priority:'event'});
      if (window.console && console.warn) console.warn('shinyOAuth: failed to set browser token cookie:', e);
    }
  }

  function handleClearBrowserToken(payload){
    var sameSite = payload.sameSite || 'Strict';
    // Default to the same fixed root path when none is supplied
    var cfg = (payload.path === undefined || payload.path === null || payload.path === '') ? '/' : String(payload.path);
    var cookiePath = normPath(cfg, /*defaultToRoot*/ true);
    var inst = String(payload.instance || '');
    // When instance is empty, clear the base cookie name (no suffix).
    // This covers module instances without a namespace suffix and
    // sanitized IDs that collapse to empty.
    var base = 'shinyOAuth_sid';
    var target = inst ? (base + '-' + inst) : base;
    clearCookiesFor(target, sameSite, cookiePath);
    // Also clear the mirrored Shiny input so a subsequent set with the same
    // value is not suppressed by client-side de-duplication.
    try {
      var shiny = ensureShiny();
      if (shiny && payload.inputId) {
        shiny.setInputValue(payload.inputId, null, {priority:'event'});
      }
    } catch(e) { /* ignore */ }
  }

  function handleRedirect(payload){
    if (!payload || !payload.url) return;
    window.location.assign(String(payload.url));
  }

  function handleClearQueryAndFixTitle(payload){
    var titleReplacement = payload && payload.titleReplacement;
    var cleanTitle = !!(payload && payload.cleanTitle);
    try {
      if (typeof titleReplacement === 'string') {
        document.title = titleReplacement;
      } else if (cleanTitle) {
        var t=document.title||'';
        var href=window.location.href;
        if(t===''||t===href){document.title=window.location.host+window.location.pathname;}else{
          var i=t.indexOf('?'); if(i>-1){document.title=t.substring(0,i);} }
      }
    } catch(e) {}

    try{
      var u=new URL(window.location.href);
      var drop=['code','state','session_state','id_token','access_token','token_type','expires_in','error','error_description','error_uri','iss'];
      for(var i=0;i<drop.length;i++){u.searchParams.delete(drop[i]);}
      var h=window.location.hash||'';
      if(h && h.indexOf('#/')===0){
        var qidx=h.indexOf('?');
        if(qidx>-1){
          var hpath=h.substring(0,qidx);
          var hq=h.substring(qidx+1);
          var parts=hq?hq.split('&'):[];
          var kept=[];
          for(var j=0;j<parts.length;j++){
            var kv=parts[j].split('=');
            if(kv.length===2){
              var k=decodeURIComponent(kv[0].replace(/\+/g,' '));
              if(drop.indexOf(k)===-1){kept.push(parts[j]);}
            }else if(parts[j]){kept.push(parts[j]);}
          }
          u.hash=kept.length ? hpath+'?'+kept.join('&') : hpath;
        }
      }else if(h){
        var hp=h.replace(/^#/,'');
        if(hp && (hp.indexOf('=')>-1)){
          var parts=hp.split('&');
          var kept=[];
          for(var j=0;j<parts.length;j++){
            var kv=parts[j].split('=');
            if(kv.length===2){
              var k=decodeURIComponent(kv[0].replace(/\+/g,' '));
              if(drop.indexOf(k)===-1){kept.push(parts[j]);}
            }else{kept.push(parts[j]);}
          }
          u.hash=kept.length ? '#'+kept.join('&') : '';
        }
      }
      window.history.replaceState({}, document.title, u.pathname + u.search + u.hash);
    }catch(e){
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }

  function register(){
    if (!window.Shiny || !Shiny.addCustomMessageHandler) {
      // In case Shiny is not yet ready, retry shortly
      setTimeout(register, 100);
      return;
    }
    Shiny.addCustomMessageHandler('shinyOAuth:setBrowserToken', handleSetBrowserToken);
    Shiny.addCustomMessageHandler('shinyOAuth:clearBrowserToken', handleClearBrowserToken);
    Shiny.addCustomMessageHandler('shinyOAuth:redirect', handleRedirect);
    Shiny.addCustomMessageHandler('shinyOAuth:clearQueryAndFixTitle', handleClearQueryAndFixTitle);
  }

  register();
})();
