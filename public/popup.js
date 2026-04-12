/**
 * Lead-Gen Call Popup — shared utility
 *
 * Usage: call initPopup(config) anywhere after DOMContentLoaded.
 * Config options:
 *   logoUrl    {string}  URL of channel logo image
 *   logoAlt    {string}  Alt text for the logo
 *   logoText   {string}  Fallback text if logo fails to load
 *   service    {string}  Service display name, e.g. "Paramount+"
 *   phone      {string}  Display phone number, e.g. "+1 888 779 1904"
 *   phoneTel   {string}  tel: href value, e.g. "+18887791904"
 *   delay      {number}  Milliseconds before popup opens (default 1500)
 *
 * Google Ads policy notes:
 *  - Popup fires on 'load' event (after full page load), never before.
 *  - Always dismissible via ×, ESC, outside click, or dismiss link.
 *  - Underlying page content is always accessible after close.
 */
(function () {
    'use strict';

    function initPopup(cfg) {
        /* POPUP DISABLED — re-enable by removing this return */
        return;

        var config = Object.assign({
            logoUrl:   '',
            logoAlt:   '',
            logoText:  '',
            service:   'this service',
            phone:     '+1 888 779 1904',
            phoneTel:  '+18887791904',
            delay:     1500
        }, cfg);

        /* ── Build DOM ── */
        var overlay = document.createElement('div');
        overlay.id = 'ctaOverlay';
        overlay.setAttribute('role', 'dialog');
        overlay.setAttribute('aria-modal', 'true');
        overlay.setAttribute('aria-label', 'Call us for help with ' + config.service);

        overlay.innerHTML = [
            '<div id="ctaModal">',
            '  <button id="ctaClose" aria-label="Close">&times;</button>',
            '  <div id="ctaLogoWrap">',
            '    <img id="ctaLogo" src="' + config.logoUrl + '" alt="' + config.logoAlt + '">',
            '    <span id="ctaLogoText">' + (config.logoText || config.service) + '</span>',
            '  </div>',
            '  <div id="ctaHeadline">' + config.service + ' Not Working?</div>',
            '  <div id="ctaSub">Our team is ready to help you right now &mdash; no waiting, no hold music.</div>',
            '  <a id="ctaCallBtn" href="tel:' + config.phoneTel + '">',
            '    <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">',
            '      <path d="M6.62 10.79c1.44 2.83 3.76 5.14 6.59 6.59l2.2-2.2c.27-.27.67-.36 1.02-.24',
            '        1.12.37 2.33.57 3.57.57.55 0 1 .45 1 1V20c0 .55-.45 1-1 1-9.39 0-17-7.61-17-17',
            '        0-.55.45-1 1-1h3.5c.55 0 1 .45 1 1 0 1.25.2 2.45.57 3.57.11.35.03.74-.25 1.02l-2.2 2.2z"/>',
            '    </svg>',
            '    Call ' + config.phone,
            '  </a>',
            '  <div id="ctaAvail">Available 24/7 &mdash; Real People, Real Help</div>',
            '  <a id="ctaDismiss" role="button" tabindex="0">Continue browsing &rarr;</a>',
            '  <div id="ctaDisclaimer">',
            '    Third-party support service. Not the official ' + config.service + ' support.',
            '  </div>',
            '</div>'
        ].join('\n');

        document.body.appendChild(overlay);

        /* ── Logo fallback ── */
        var logoImg  = document.getElementById('ctaLogo');
        var logoText = document.getElementById('ctaLogoText');
        if (!config.logoUrl) {
            logoImg.style.display  = 'none';
            logoText.style.display = 'block';
        } else {
            logoImg.onerror = function () {
                logoImg.style.display  = 'none';
                logoText.style.display = 'block';
            };
        }

        /* ── Open / close helpers ── */
        function openPopup() {
            overlay.classList.add('active');
            document.body.style.overflow = 'hidden';
            var closeBtn = document.getElementById('ctaClose');
            if (closeBtn) closeBtn.focus();
        }

        function closePopup() {
            overlay.classList.remove('active');
            document.body.style.overflow = '';
        }

        /* ── Google Ads conversion — exact snippet from Google Ads dashboard ── */
        function gtag_report_conversion(url) {
            var callback = function () {
                if (typeof(url) !== 'undefined') {
                    window.location = url;
                }
            };
            if (typeof gtag === 'function') {
                gtag('event', 'conversion', {
                    'send_to': 'AW-11546748562/0VO9CImIrfsbEJLN9YEr',
                    'value': 1.0,
                    'currency': 'INR',
                    'event_callback': callback
                });
            } else {
                callback();
            }
            return false;
        }

        /* ── Event listeners ── */
        document.getElementById('ctaCallBtn').addEventListener('click', function (e) {
            e.preventDefault();
            gtag_report_conversion(this.href);
        });

        document.getElementById('ctaClose').addEventListener('click', closePopup);

        document.getElementById('ctaDismiss').addEventListener('click', closePopup);
        document.getElementById('ctaDismiss').addEventListener('keydown', function (e) {
            if (e.key === 'Enter' || e.key === ' ') closePopup();
        });

        overlay.addEventListener('click', function (e) {
            if (e.target === overlay) closePopup();
        });

        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') closePopup();
        });

        /* ── Delayed open — fires on window load (Google Ads compliant) ── */
        function scheduleOpen() {
            setTimeout(openPopup, config.delay);
        }

        if (document.readyState === 'complete') {
            scheduleOpen();
        } else {
            window.addEventListener('load', scheduleOpen);
        }
    }

    /* Expose globally */
    window.initPopup = initPopup;
})();
