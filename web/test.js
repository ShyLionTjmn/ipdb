function has_right() { return true; };
const R_SUPER="r_super";
const color_table_buttons="green";

function sites_list(presel, opt, donefunc) {

  let title;

  if(has_right(R_SUPER)) {
    title = "Управление сайтами";
  } else {
    if(donefunc != undefined) {
      title = "Выбор сайта";
    } else {
      title = "Просмотр сайтов";
    };
  };

  let dialog=$(DIV).myid("sites_list")
   .data("opt", opt)
   .data("donefunc", donefunc)
   .data("presel", presel)
   .addClass("dialog_start")
   .prop("title", title)
   .css({"white-space": "pre", "font-size": "larger"})
   .appendTo("BODY")
  ;

  let d={
    modal:true,
    position: { my: "center top", at: "center top", of: window },
    maxHeight: $(window).height(),
    minHeight: $(window).height()-10,
    minWidth:1000,
    buttons: [],
    close: function() {
      //unwatch(TICK_site, 0);
      let did=$(this).prop("id");
      $(this).dialog("destroy");
      $(this).remove();
      $(window).off("resize."+did);
    },
    open: function() {
      let _dialog=$(this);
      let did=$(this).prop("id");
      $(window).on("resize."+did, function() {
        _dialog.dialog("option", "maxHeight", $(window).height());
        _dialog.dialog("option", "minHeight", $(window).height() - 10);
      });
      $(this).dialog("widget").find(".confirm_btn").prop('disabled', true).css({"color": "gray"});
    }
  };

  let head;

  dialog
   .append( head = $(DIV)
     .css({"padding-bottom": "0.5em"})
   )
  ;

  if(has_right(R_SUPER)) {
    head
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-plusthick").addClass("ui-button")
       .css({"color": color_table_buttons, "margin-right": "0.5em", "padding": "0.1em"})
       .title( "Добавить корневой сайт" )
       .click(function() {
         let ref = $("#tree").jstree(true);
         if(ref === false) { error_at(); return; };


         let new_id = ref.create_node("#", {"text": "Переименовать"}, "last");
         ref.deselect_all(true);
         ref.select_node( new_id );
         ref.edit( new_id );
       })
     )
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-plus").addClass("ui-button").addClass("site_selected_btn")
       .css({"color": "lightgray", "margin-right": "0.5em", "padding": "0.1em"})
       .title( "Добавить вложенный сайт" )
       .click(function() {
         let ref = $("#tree").jstree(true);
         if(ref === false) { error_at(); return; };
         let selected_ids=ref.get_selected();
         if(selected_ids.length == 0) { return; };
         let new_id = ref.create_node(selected_ids[0], {"text": "Переименовать"}, "last");
         ref.deselect_all(true);
         ref.select_node( new_id );
         ref.edit( new_id );
       })
     )
    ;
  };
  head
   .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-bullets").addClass("ui-button").addClass("site_selected_btn")
     .css({"color": "lightgray", "margin-right": "0.5em", "padding": "0.1em"})
     .title( "Свойства сайта" )
     .click(function() {
       let ref = $("#tree").jstree(true);
       if(ref === false) { error_at(); return; };
       let selected_ids=ref.get_selected();
       if(selected_ids.length == 0) { return; };
     })
   )
  ;

  //dialog.dialog(d);

  dialog
   .append( tree=$(DIV).myid("tree")
     .css({})
     .jstree({
       "core": {
         "check_callback": true,
         "multiple": false
       },
       "types": {
         "default": {
           "valid_children" : ["default"]
         }
       },
       //"plugins" : [ "wholerow", "contextmenu", "dnd" ]
       "plugins" : [ "contextmenu", "dnd", "types" ]
     })
     .on("changed.jstree", function(e, data) {
       if(data.selected.length > 0) {
         $(this).closest(".dialog_start").find(".site_selected_btn").css({"color": color_table_buttons});
       } else {
         $(this).closest(".dialog_start").find(".site_selected_btn").css({"color": "lightgray"});
       };
     })
   )
  ;
};


$( document ).ready(function() {

  sites_list();
/*
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
     "plugins" : [ "wholerow", "dnd" ]
   })
  ;
*/
});
