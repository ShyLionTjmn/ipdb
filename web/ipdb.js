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

const color_odd="#FFE0FF";
const color_even="#E0FFFF";


const v4len2mask=[
  0, //0.0.0.0
  2147483648, //128.0.0.0
  3221225472, //192.0.0.0
  3758096384, //224.0.0.0
  4026531840, //240.0.0.0
  4160749568, //248.0.0.0
  4227858432, //252.0.0.0
  4261412864, //254.0.0.0
  4278190080, //255.0.0.0
  4286578688, //255.128.0.0
  4290772992, //255.192.0.0
  4292870144, //255.224.0.0
  4293918720, //255.240.0.0
  4294443008, //255.248.0.0
  4294705152, //255.252.0.0
  4294836224, //255.254.0.0
  4294901760, //255.255.0.0
  4294934528, //255.255.128.0
  4294950912, //255.255.192.0
  4294959104, //255.255.224.0
  4294963200, //255.255.240.0
  4294965248, //255.255.248.0
  4294966272, //255.255.252.0
  4294966784, //255.255.254.0
  4294967040, //255.255.255.0
  4294967168, //255.255.255.128
  4294967232, //255.255.255.192
  4294967264, //255.255.255.224
  4294967280, //255.255.255.240
  4294967288, //255.255.255.248
  4294967292, //255.255.255.252
  4294967294, //255.255.255.254
  4294967295 //255.255.255.255
];

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
   .css({"border-collapse": "collapse", "font-size": "large", "border": "1px solid #222222"})
   .appendTo(contents)
  ;

  let thead=$(THEAD)
   .appendTo(table)
  ;
  let htr=$(TR)
   .css({"position": "relative", "background-color": "white"})
   .appendTo(thead)
  ;

  let masklen_start = data['net_info']['masklen'] + 1;
  let masklen_stop;

  let first_ip_octets=ip4octets(data['net_info']['net']);
  let last_ip_octets=ip4octets(data['net_info']['net_last']);

  let octet_index;

  if(data['net_info']['masklen'] < 8) {
    masklen_stop = 8;
    octet_index = 0;
  } else if(data['net_info']['masklen'] < 16) {
    masklen_stop = 16;
    octet_index = 1;
  } else if(data['net_info']['masklen'] < 24) {
    masklen_stop = 24;
    octet_index = 2;
  } else {
    masklen_stop = 32;
    octet_index = 3;
  };

  let first_octet=first_ip_octets[octet_index];
  let last_octet=last_ip_octets[octet_index];

  $(TH).text("") //top-left corner
   .css({"position": "sticky", "top": "0", "background-color": "white", "z-index": 1000000, "border-bottom": "1px solid gray"})
   .appendTo(htr)
  ;

  for(let i=masklen_start; i <= masklen_stop; i++) {
    $(TH).text("/"+i)
     .css({"position": "sticky", "top": "0", "background-color": "white", "z-index": 1000000, "border-bottom": "1px solid gray", "border-left": "1px solid gray"})
     .appendTo(htr)
    ;
  };

  //last column
  $(TH)
   .css({"position": "sticky", "top": "0", "background-color": "white", "z-index": 1000000, "border-bottom": "1px solid gray", "border-left": "1px solid gray"})
   .appendTo(htr)
  ;

  let tbody=$(TBODY)
   .appendTo(table)
  ;

  let rows_octets=first_ip_octets.slice();

  let last_net=undefined;

  for(let o=first_octet; o <= last_octet; o++) {
    let tr=$(TR);

    if(o % 2) {
      tr.css({"background-color": color_odd});
    } else {
      tr.css({"background-color": color_even});
    };

    rows_octets[octet_index] = o;

    let row_ip_text=rows_octets[0]+"."+rows_octets[1]+"."+rows_octets[2]+"."+rows_octets[3];

    let row_net=v4oct2long(rows_octets[0], rows_octets[1], rows_octets[2], rows_octets[3]);

    tr
     .append( $(TD).text(row_ip_text)
       .css({"border-bottom": "1px solid gray"})
     )
    ;
    for(let i=masklen_start; i <= masklen_stop; i++) {
      let cell_text="";
      let cell_style={"color": "blue"};

      let mask_net = (row_net & v4len2mask[i]) >>> 0;
      let mask_net_last = (mask_net | (~v4len2mask[i] >>> 0)) >>> 0;


      let taken= (last_net != undefined &&
         mask_net >= last_net['v4net_addr'] &&
         mask_net <= last_net['v4net_last']
      );

      let view = false;

      if(!taken &&
         data['nets'][ mask_net ] !== undefined &&
         data['nets'][ mask_net ]['v4net_mask'] == i
      ) {
        taken = true;
        last_net = data['nets'][ mask_net ];
        last_net_octets=ip4octets(mask_net);
        last_net['net_text']=last_net_octets[0]+"."+last_net_octets[1]+"."+last_net_octets[2]+"."+last_net_octets[3];
        view=true;
      };

      //let takable= (row_net == mask_net) && !taken && data['aggr_nets'][ row_net ] == undefined;
      let takable= (row_net == mask_net) && !taken;

      if(takable && data['aggr_nets'][ row_net ] != undefined) {
        takable = false;
        cell_style['background-color']="lightgray";
      };

      if(takable) {
        for(n in data['nets']) {
          if(data['nets'][n]['v4net_addr'] >= mask_net && data['nets'][n]['v4net_addr'] <= mask_net_last) {
            takable = false;
            cell_style['background-color']="lightgray";
            break;
          };
        };
      };

      let navigatable = (row_net == mask_net) && !taken && (i < 32);

      if(taken) {
        cell_style['background-color']="lightgray";
      };

      let td=$(TD)
       .css({"border-bottom": "1px solid gray", "border-left": "1px solid gray"})
      ;

      if(taken) {
        if(view) {
          td
           .append( $(SPAN).addClass("ui-icon").addClass("ui-icon-bullets")
             .title("Перейти к просмотру сети "+row_ip_text+"/"+i)
           )
          ;
        } else {
          td.title("Входит в сеть "+last_net['net_text']+"/"+last_net['v4net_mask']);
        };
      } else {
        if(takable) {
          td
           .append( $(SPAN).addClass("ui-icon").addClass("ui-icon-cart")
             .title("Занять сеть "+row_ip_text+"/"+i)
           )
          ;
        };
        if(navigatable) {
          td
           .append( $(SPAN).addClass("ui-icon").addClass("ui-icon-sitemap")
             .title("Навигация по подсетям "+row_ip_text+"/"+i)
           )
          ;
        };
      };

      td
       .css(cell_style)
       .appendTo(tr)
      ;
    };

    let net_name="";
    
    if(data['nets'][ row_net ] !== undefined) {
      net_name=data['nets'][ row_net ]['v4net_name'];
    } else if(data['aggr_nets'][ row_net ] !== undefined) {
      net_name = "... " + data['aggr_nets'][ row_net ]['aggr_count'] + " " + nets2lang(false, 'ru', data['aggr_nets'][ row_net ]['aggr_count']);
    };

    tr
     .append( $(TD).text(net_name)
       .css({"border-bottom": "1px solid gray", "border-left": "1px solid gray"})
     )
    ;

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
       "border": "1px solid black",
       "z-index": 1000000
     })
     .click(function() {
       $("#debug").toggle();
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
