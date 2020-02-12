var ud;

const R_SUPER='r_super';
const R_VIEWANY='r_viewany';

const NR_VIEWNAME       = 1 << 0;
const NR_VIEWOTHER      = 1 << 1;
const NR_TAKE_IP        = 1 << 2;
const NR_EDIT_IP        = NR_TAKE_IP;
const NR_FREE_IP        = 1 << 3;
const NR_IGNORE         = 1 << 4;
const NR_MAN_ACCESS     = 1 << 5; 
const NR_MAN_RANGES     = 1 << 6;
const NR_DROP_NET       = 1 << 7;
const NR_EDIT_NET       = 1 << 8;


const s_blocks_border_color={"border-color": "rgb(79, 129, 189)"};
const s_blocks_color={"color": "rgb(79, 129, 189)"};

function v4oct2long(i3, i2, i1, i0) {
  let ret = (0xFF & i3) << 24;
  ret += (0xFF & i2) << 16;
  ret += (0xFF & i1) << 8;
  ret += (0xFF & i0);
  return ret >>> 0;
};

function has_right(right, rightstr) {
  if(rightstr === undefined) { rightstr=ud['user']['rights']; };
  if(rightstr.indexOf(R_SUPER) >= 0 || rightstr.indexOf(right) >= 0) {
    return true;
  } else {
    return false;
  };
};

function ip4octets(net) {
  let ret=[];
  ret[0] = net >>> 24;
  ret[1] = (net >>> 16) & 0xFF;
  ret[2] = (net >>> 8) & 0xFF;
  ret[3] = net & 0xFF;
  return ret;
};

function v4nav(data) {
  let contents=$("#ipv4");
  if(contents.length != 1) {
    error_at();
    return;
  };

  contents.empty();

  $("#page_title").text("IPv4 v4nav");

  let table=$(TABLE)
   .appendTo(contents)
  ;

  let thead=$(THEAD)
   .appendTo(table)
  ;
  let htr=$(TR)
   .appendTo(thead)
  ;

  let masklen_start = data['net_info']['masklen'] + 1;
  let masklen_stop;

  let first_ip_octets=ip4octets(data['net_info']['net']);
  let last_ip_octets=ip4octets(data['net_info']['net_last']);

  let first_octet;
  let last_octet;

  if(data['net_info']['masklen'] < 8) {
    masklen_stop = 8;
    first_octet=first_ip_octets[0];
    last_octet=last_ip_octets[0];
  } else if(data['net_info']['masklen'] < 16) {
    masklen_stop = 16;
    first_octet=first_ip_octets[1];
    last_octet=last_ip_octets[1];
  } else if(data['net_info']['masklen'] < 24) {
    masklen_stop = 24;
    first_octet=first_ip_octets[2];
    last_octet=last_ip_octets[2];
  } else {
    masklen_stop = 32;
    first_octet=first_ip_octets[3];
    last_octet=last_ip_octets[3];
  };

  $(TH).text("") //top-left corner
   .appendTo(htr)
  ;

  for(let i=masklen_start; i <= masklen_stop; i++) {
    $(TH).text("/"+i)
     .appendTo(htr)
    ;
  };

  let tbody=$(TBODY)
   .appendTo(table)
  ;

  for(let o=first_octet; o <= last_octet; o++) {
    let tr=$(TR);
    tr.append( $(TD).text(o) );
    for(let i=masklen_start; i <= masklen_stop; i++) {
      $(TD).text(i)
       .appendTo(tr)
      ;
    };

    tr.appendTo(tbody);
  };
};

function v4view(data) {
  return;
  let contents=$("#ipv4");
  if(contents.length != 1) {
    error_at();
    return;
  };

  contents.empty();

  $("#page_title").text("IPv4 view");
};

function v4get_net(net, masklen) {
  run_query({"action": "v4get_net", "net": net, "mask": masklen}, function(data) {
    if(data["ok"]["type"] == "nav") {
      v4nav(data["ok"]);
    } else {
      v4view(data["ok"]);
    };
  });
};

function ipv4() {
  let contents=$("#ipv4");
  if(contents.length != 1) {
    error_at();
    return;
  };

  $("#page_title").text("IPv4");

  contents.empty();

  $(DIV)
   .css({"display": "inline-block", "margin": "5px", "border": "3px solid", "border-radius": "5px", "vertical-align": "top"})
   .css(s_blocks_border_color)
   .append( $(DIV)
     .css({"border-bottom": "2px solid"})
     .css(s_blocks_border_color)
     .append( $(DIV)
       .css({"padding-right": "5px", "display": "inline-block"})
       .append( $(SPAN).addClass("ui-icon").addClass("ui-icon-sitemap").css(s_blocks_color) )
     )
     .append( $(DIV)
       .css({"display": "inline-block", "border-left": "2px solid"})
       .css(s_blocks_border_color)
       .append( $(SPAN).text("Навигация").css({"font-size": "larger", "margin-left": "0.5em", "margin-right": "0.5em"}) )
     )
   )
   .append( $(TABLE)
     .append( $(TR)
       .append( $(TD)
         .append( $(SPAN).text("0.0.0.0/0").title("Перейти к навигации по подсетям") )
       )
       .append( $(TD)
         .append( $(BUTTON).button({"icon": "ui-icon-sitemap"})
           .title("Перейти к навигации по подсетям")
           .css({"padding-left": "0.5em", "padding-right": "0.5em", "margin-left": "1em"})
           .click(function() {
             v4get_net(0, 0);
           })
         )
       )
     )
     .append( $(TR)
       .append( $(TD)
         .append( $(INPUT).id("v4goto_net").prop({"placeholder": "x.x.x.x/mm", "type": "search"})
           .title("Введите адрес сети в CIDR нотации. Если сеть не существует, интерфейс перейдет в режим навигации ближайшей в сторону увеличения сети, либо к просмотру/редактированию существующей сети")
           .enterKey(function() { $("#v4goto_net_btn").trigger("click"); })
         )
       )
       .append( $(TD)
         .append( $(BUTTON).button({"icon": "ui-icon-sitemap"}).id("v4goto_net_btn")
           .title("Перейти к навигации по указаной подсети")
           .css({"padding-left": "0.5em", "padding-right": "0.5em", "margin-left": "1em"})
           .click(function() {
             let val=$("#v4goto_net").val();
             if(val === undefined) { error_at(); return; };
             let match=String(val).match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
             if(match === null) {
               $("#v4goto_net").animateHighlight();
               return;
             };
             if(match.length != 6) { error_at(); return; };
             if(Number(match[1]) > 255 || Number(match[2]) > 255 || Number(match[3]) > 255 || Number(match[4]) > 255 || Number(match[5]) > 32) {
               $("#v4goto_net").animateHighlight();
               return;
             };
             v4get_net( v4oct2long(Number(match[1]), Number(match[2]), Number(match[3]), Number(match[4])), Number(match[5]) );
           })
         )
       )
     )
   )
   .appendTo( contents )
  ;

  $(DIV)
   .css({"display": "inline-block", "margin": "5px", "border": "3px solid", "border-radius": "5px", "vertical-align": "top"})
   .css(s_blocks_border_color)
   .append( $(DIV)
     .css({"border-bottom": "2px solid"})
     .css(s_blocks_border_color)
     .append( $(DIV)
       .css({"padding-right": "5px", "display": "inline-block"})
       .append( $(SPAN).addClass("ui-icon").addClass("ui-icon-bookmark").css(s_blocks_color) )
     )
     .append( $(DIV)
       .css({"display": "inline-block", "border-left": "2px solid"})
       .css(s_blocks_border_color)
       .append( $(SPAN).text("Избранное").css({"font-size": "larger", "margin-left": "0.5em", "margin-right": "0.5em"}) )
     )
   )
   .append( $(DIV).text("To Do")
   )
   .appendTo( contents )
  ;

  $(BR).appendTo( contents );

  $(DIV)
   .css({"display": "inline-block", "margin": "5px", "border": "3px solid", "border-radius": "5px", "vertical-align": "top"})
   .css(s_blocks_border_color)
   .append( $(DIV)
     .css({"border-bottom": "2px solid"})
     .css(s_blocks_border_color)
     .append( $(DIV)
       .css({"padding-right": "5px", "display": "inline-block"})
       .append( $(SPAN).addClass("ui-icon").addClass("ui-icon-search").css(s_blocks_color) )
     )
     .append( $(DIV)
       .css({"display": "inline-block", "border-left": "2px solid"})
       .css(s_blocks_border_color)
       .append( $(SPAN).text("Поиск").css({"font-size": "larger", "margin-left": "0.5em", "margin-right": "0.5em"}) )
     )
   )
   .append( $(DIV).text("To Do")
   )
   .appendTo( contents )
  ;
};

$( document ).ready(function() {
  $("BODY")
   .append( $(DIV).id("debug")
     .css({
       "position": "absolute", "right": "1em", "top": "1em", "width": "600px", "height": "600px",
       "border": "1px solid black",
       "overflow": "scroll",
       "white-space": "pre"
     })
   )
   .append( $(DIV).id("led")
     .css({
       "position": "absolute", "right": "0em", "top": "0em", "width": "1em", "height": "1em",
       "border": "1px solid black"
     })
   )
   .append( $(DIV).id("page_title")
     .css({
       "position": "absolute", "right": "0em", "top": "0em", "left": "0em",
       "text-align": "center", "font-size": "3em"
     })
   )
  ;


  run_query({"action": "check_auth"}, function(data) {
    ud=data["ok"];
    if(data["ok"]["status"] == "unauth") {
      showLoginWindow(data["ok"]["providers"], "Необходимо пройти авторизацию.");
    } else {

      let menu_bar = $(DIV).id("top_menu")
       .css({"border": "1px solid lightgray", "display": "inline-block", "margin-left": "5px", "padding": "5px", "background-color": "white"})
       .hide()
       .click(function(e) {
         e.stopPropagation();
         $("#top_menu").hide();
         $("#user_info").show();
         //$(this).find(".popup_submenu").toggle();
       })
      ;

      $(DIV).css({"position": "absolute", "top": "0px", "left": "0px", "font-size": "150%", "padding": "5px"})
       .append( $(DIV).css({"display": "inline-block", "padding": "6px"})
         .append( $(SPAN).addClass("ui-button").addClass("ui-icon").addClass("ui-icon-menu")
           .css({"color": "#4f81bd", "font-size": "inherit"})
           .click(function() {
             $("#top_menu").toggle();
             $("#user_info").toggle();
           })
         )
       )
       .append( menu_bar )
       .append( $(DIV).id("user_info")
         .css({"border": "1px solid lightgray", "display": "inline-block", "margin-left": "5px", "padding": "5px", "background-color": "white"})
       )
       .appendTo( $("BODY") )
      ;

      menu_bar
       .append( $(SPAN).addClass("ui-button").addClass("ui-icon").addClass("ui-icon-sign-out")
         .title("Выход")
         .css({"font-size": "inherit"})
         .click(function() {
           //$("#top_menu").hide();
           //$(this).find(".popup_submenu").toggle();
           let ipdb_uri=window.location.href.split("/").slice(0, -1).join("/") + "/";

           window.location.href="logout.php?back_uri="+encodeURIComponent(ipdb_uri);
         })
       )
       .append( $(SPAN).addClass("ui-button").text("Button")
         .css({"padding": "0px 0.3em", "margin-left": "10px"})
         .click(function() {
           //$("#top_menu").hide();
           //$(this).find(".popup_submenu").toggle();
         })
       )
      ;

      $("#user_info").text(data["ok"]["user"]["user_name"]);


      if(data["ok"]["user"]["user_state"] < 1) {
        let message;
        switch(Number(data["ok"]["user"]["user_state"])) {
        case 0:
          message="Пользователь отключен администратором.";
          break;
        case -1:
          message="Пользователь добавлен автоматически.\nОбратитесь к администратору для активации.";
          break;
        default:
          message="Пользователь удален администратором.";
        };

        message += "\nId пользователя: "+data["ok"]["user"]["user_id"];

        show_dialog(message);
      } else {
        if(has_right(R_SUPER)) {
          $("#user_info").append( $(SPAN).addClass("ui-icon").addClass("ui-icon-wrench").title("Super user!").css({"color": "gray", "margin-left": "0.5em"}) );
        } else {
          if(has_right(R_VIEWANY)) {
            $("#user_info").append( $(SPAN).addClass("ui-icon").addClass("ui-icon-eye").title("Can view all nets").css({"color": "gray", "margin-left": "0.5em"}) );
          };
        };
        // continue building of document structure
        $(DIV).id("ipv4")
         .css({"margin-top": "3em"})
         .appendTo("BODY")
        ;
        menu_bar
         .append( $(SPAN).addClass("ui-button").text("IPv4")
           .css({"padding": "0px 0.3em", "margin-left": "10px"})
           .click(function() {
             ipv4();
           })
         )
        ;

        ipv4();
      };

    };
  });

});
