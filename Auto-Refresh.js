// ==UserScript==
// @name         Silent Tab-Specific Random Auto-Refresh
// @namespace    https://scriptcat.org/
// @version      2.0
// @description  Hard-refreshes ONLY the activated tab. No visible popups. Activated via Alt + R.
// @match        *://*.YOUR-WEBSITE-DOMAIN.com/*
// @grant        GM_registerMenuCommand
// @run-at       document-idle
// ==/UserScript==

(function() {
    'use strict';

    // ==========================================
    // ⚙️ CONFIGURATION SETTINGS
    // ==========================================

    // 1. Set your delay range in SECONDS (100 to 200)
    const minSeconds = 100; 
    const maxSeconds = 200; 

    // 2. Paste the EXACT URL you want to enforce
    const targetURL = "https://ENTER-YOUR-EXACT-URL-HERE.com";

    // ==========================================
    // DO NOT EDIT BELOW
    // ==========================================

    const randomSeconds = Math.floor(Math.random() * (maxSeconds - minSeconds + 1)) + minSeconds;
    const delayMilliseconds = randomSeconds * 1000;
    let timerId = null;

    // Creates a temporary message that disappears after 3 seconds
    function showToast(message, bgColor) {
        const toast = document.createElement('div');
        toast.innerText = message;
        toast.style.position = 'fixed';
        toast.style.bottom = '20px';
        toast.style.right = '20px';
        toast.style.zIndex = '999999';
        toast.style.padding = '12px 20px';
        toast.style.background = bgColor;
        toast.style.color = '#fff';
        toast.style.borderRadius = '5px';
        toast.style.fontWeight = 'bold';
        toast.style.fontFamily = 'Arial, sans-serif';
        toast.style.boxShadow = "0px 4px 6px rgba(0,0,0,0.3)";
        document.body.appendChild(toast);

        // Delete the message completely after 3 seconds
        setTimeout(() => { toast.remove(); }, 3000);
    }

    function doHardRefresh() {
        const separator = targetURL.includes('?') ? '&' : '?';
        window.location.href = targetURL + separator + "nocache=" + Date.now();
    }

    // Function to turn the script on or off
    function toggleRefresh() {
        const isActive = sessionStorage.getItem('scriptcat_tab_active') === 'true';

        if (isActive) {
            sessionStorage.setItem('scriptcat_tab_active', 'false');
            clearTimeout(timerId);
            showToast('🛑 Auto-Refresh STOPPED in this tab', '#ff4c4c');
        } else {
            sessionStorage.setItem('scriptcat_tab_active', 'true');
            showToast(`▶️ Auto-Refresh STARTED! Next in ~${randomSeconds}s`, '#4caf50');
            timerId = setTimeout(doHardRefresh, delayMilliseconds);
        }
    }

    // Option 1: Adds a clickable button inside the ScriptCat extension menu
    if (typeof GM_registerMenuCommand !== "undefined") {
        GM_registerMenuCommand("Toggle Auto-Refresh for this Tab", toggleRefresh);
    }

    // Option 2: Keyboard Shortcut (Alt + R)
    document.addEventListener('keydown', function(e) {
        if (e.altKey && (e.key === 'r' || e.key === 'R')) {
            toggleRefresh();
        }
    });

    // If active, automatically start the timer silently in the background
    if (sessionStorage.getItem('scriptcat_tab_active') === 'true') {
        console.log(`Silent Auto-Refresh active. Reloading in ${randomSeconds} seconds.`);
        timerId = setTimeout(doHardRefresh, delayMilliseconds);
    }

})();
