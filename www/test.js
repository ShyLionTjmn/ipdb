'use strict';

var body;
$( document ).ready(function() {

  body=$( "body" );

  history.pushState(undefined, undefined, "?action=moo");

  let action=getUrlParameter("action");

  body.text(action);
});
