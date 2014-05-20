// Fullscreen API Shim adapted from:
// https://github.com/toji/game-shim/blob/master/game-shim.js

var elementPrototype = (window.HTMLElement || window.Element)["prototype"];
var getter;
window.fullscreenSupport = true;

// document.isFullScreen
if(!document.hasOwnProperty("fullscreenEnabled")) {
    getter = (function() {
        // These are the functions that match the spec, and should be preferred
        if("webkitIsFullScreen" in document) {
            return function() { return document.webkitIsFullScreen; };
        }
        if("mozFullScreen" in document) {
            return function() { return document.mozFullScreen; };
        }

        window.fullscreenSupport = false;
        return function() { return false; }; // not supported, never fullscreen
    })();
    
    Object.defineProperty(document, "fullscreenEnabled", {
        enumerable: true, configurable: false, writeable: false,
        get: getter
    });
}

if(!document.hasOwnProperty("fullscreenElement")) {
    getter = (function() {
        // These are the functions that match the spec, and should be preferred
        if("webkitFullscreenElement" in document) {
            return function() { return document.webkitFullscreenElement; };
        }
        if("mozFullscreenElement" in document) {
            return function() { return document.mozFullscreenElement; };
        }
        return function() { return null; }; // not supported
    })();
    
    Object.defineProperty(document, "fullscreenElement", {
        enumerable: true, configurable: false, writeable: false,
        get: getter
    });
}

// Document event: fullscreenchange
function fullscreenchange(oldEvent) {
    var newEvent = document.createEvent("CustomEvent");
    newEvent.initCustomEvent("fullscreenchange", true, false, null);
    // TODO: Any need for variable copy?
    document.dispatchEvent(newEvent);
}
document.addEventListener("webkitfullscreenchange", fullscreenchange, false);
document.addEventListener("mozfullscreenchange", fullscreenchange, false);

// Document event: fullscreenerror
function fullscreenerror(oldEvent) {
    var newEvent = document.createEvent("CustomEvent");
    newEvent.initCustomEvent("fullscreenerror", true, false, null);
    // TODO: Any need for variable copy?
    document.dispatchEvent(newEvent);
}
document.addEventListener("webkitfullscreenerror", fullscreenerror, false);
document.addEventListener("mozfullscreenerror", fullscreenerror, false);
