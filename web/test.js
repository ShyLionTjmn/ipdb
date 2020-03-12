$( document ).ready(function() {

  //sites_list();

  $("<DIV/>")
   .appendTo( "BODY" )
   .append( $("<DIV/>")
     .append( $("<LABEL/>").text("+")
       .click(function() {
         $("#tree").jstree().create_node("#", {"text": "node"}, "last");
       })
     )
   )
   .append( $("<DIV/>").prop("id", "tree")
   )
  ;

  $("#tree")
   .jstree({
     "core": {
       "check_callback": true,
     },
     "plugins" : [ "wholerow" ]
   })
  ;
});
