// Copyright 2012 Feross Aboukhadijeh (http://feross.org) (feross@feross.org)


function requestFullScreen() {
  if (elementPrototype.requestFullscreen) {
    document.documentElement.requestFullscreen();
  } else if (elementPrototype.webkitRequestFullScreen) {
    document.documentElement.webkitRequestFullScreen(Element.ALLOW_KEYBOARD_INPUT);
  } else if (elementPrototype.mozRequestFullScreen) {
    document.documentElement.mozRequestFullScreen();
  } else {
    /* fail silently */
  }
}




$(function() {

  // Preload target site image
  $('#spoofSite img').each(function(i, img) {
    var temp = new Image();
    temp.src = img.src;
  });

  // Detect if the demo will run on user's browser
  var errors = [];
  var errorStr = "";
  if (window.fullscreenSupport) {

    // Browser detect
    if (BrowserDetect.browser == "Chrome") {
      $('html').addClass('chrome');
    } else if (BrowserDetect.browser == "Firefox") {
      $('html').addClass('firefox');
    } else if (BrowserDetect.browser == "Safari") {
      $('html').addClass('safari');
    } else {
      $('html').addClass('chrome'); // fallback to wrong UI
      errors.push("Your browser supports the Fullscreen API! However, it didn't support it when I made this demo. The <b>demo will still work</b> but you will see Chrome's UI instead of your own browser's UI.");
    }

    // OS detect
    if (BrowserDetect.OS == "Mac") {
      $('html').addClass('osx');
    } else if (BrowserDetect.OS == "Windows") {
      $('html').addClass('windows');
    } else if (BrowserDetect.OS == "Linux") {
      $('html').addClass('linux');
    } else {
      errors.push("You're not using an Windows, Mac OS X, or Linux. The <b>demo will not work</b> on your OS.");
    }

  } else {
    errors.push("Your browser does not support the Fullscreen API. Sorry - this demo will not work for you. Try Chrome, Firefox, or Safari 6 (on OS X 10.8 Mountain Lion).");
  }

  // Errors?
  if (errors.length) {
    $.each(errors, function(i, error) {
      errorStr += error;
      if (i != errors.length - 1) {
        errorStr += "<br><br>";
      }
    });
  }

  // Set class on html element that represents the fullscreen state
  $(document).on('fullscreenchange', function(test) {
    if (document.fullscreenEnabled) {
      $('html').addClass('fullscreened').removeClass('not-fullscreened');
    } else {
      $('html').addClass('not-fullscreened').removeClass('fullscreened');
      $('html').off('click.spoof');
    }
  });
  $(document).trigger('fullscreenchange');

  // Handle click on target link
  $('html').on('click', '.spoofLink', function(e) {
    
    // Prevent navigation to legit link
    e.preventDefault();
    e.stopPropagation();

    // Show error if browser doesn't support fullscreen
    if (!window.fullscreenSupport) {
      $.facebox(errorStr);
      return;
    }

    // Trigger fullscreen
    requestFullScreen();

    // Set target site to proper height, based on window size
    $('#spoofSite').css({
      top: $('#spoofHeader').height(),
      height: $(window).height()
    });


    // Set target textbox to proper height, based on window size
    $('#textBox').css({
      top: $(window).height() / 2 - 100,
      left: $(window).height() / 2 + 600
    });


    // Set target textbox2 to proper height, based on window size
    $('#textBoxTwo').css({
      top: $(window).height() / 2 - 30,
      left: $(window).height() / 2 + 600
    });



    // Set target Suubmit Button to proper height, based on window size
    $('#buttonSubmit').css({
      top: $(window).height() / 2 + 15,
      left: $(window).height() / 2 + 550
    });


    // Set target textbox3 RememberME to proper height, based on window size
    $('#textBoxThree').css({
      top: $(window).height() / 2 + 25,
      left: $(window).height() / 2 + 770
    });




    // Callout when the user clicks on something from fake UI
    $('html').on('click.spoof', function() {
    //  $('#spoofHeader').stop().effect('', function() {
        //$.facebox({div: '#phished'});
    //  });

    });
  });

});

