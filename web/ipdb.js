// GLOBALS

var ud;
var $R={};
var page_root;

var _debug_opts=true;

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
const RR_TAKE_NET       = 1 << 9;
const RR_DENY_TAKE_IP   = 1 << 10; //also deny editing

const group_rights=Array(
  { "right": R_SUPER,
    "label_text": "Супер",
    "label_descr": "Полный доступ к базе данных"
  },
  { "right": R_VIEWANY,
    "label_text": "Прсмт",
    "label_descr": "Просмотр любой информации"
  },
);

const group_net_rights=Array(
  { "right": NR_VIEWNAME,
    "label_text": "Имен",
    "label_descr": "Просмотр наименований объектов"
  },
  { "right": NR_VIEWOTHER,
    "label_text": "Детл",
    "label_descr": "Просмотр детальной информации об объектах"
  },
  { "right": NR_TAKE_IP,
    "label_text": "ЗанIP",
    "label_descr": "Занятие IP адреса в сети"
  },
  { "right": NR_EDIT_IP,
    "label_text": "РедIP",
    "label_descr": "Редактирование полей IP адреса"
  },
  { "right": NR_FREE_IP,
    "label_text": "УдлIP",
    "label_descr": "Освобождение IP адреса в сети"
  },
  { "right": NR_IGNORE,
    "label_text": "Игнр",
    "label_descr": "Игнорирование запрета от диапазона в сети"
  },
  { "right": NR_MAN_ACCESS,
    "label_text": "УДост",
    "label_descr": "Управление доступом к сети"
  },
  { "right": NR_MAN_RANGES,
    "label_text": "УДиап",
    "label_descr": "Управление диапазонами в сети"
  },
  { "right": NR_DROP_NET,
    "label_text": "УдлСет",
    "label_descr": "Удаление сети"
  },
  { "right": NR_EDIT_NET,
    "label_text": "РедСет",
    "label_descr": "Редактирование данных сети"
  },
  { "right": RR_TAKE_NET,
    "label_text": "ЗанСет",
    "label_descr": "Занятие сети"
  },
  { "right": RR_DENY_TAKE_IP,
    "label_text": "ЗапрIP",
    "label_descr": "Запрет на занятие/редактирование IP внутри диапазона"
  },
);


const s_blocks_border_color={"border-color": "rgb(79, 129, 189)"};
const s_blocks_color={"color": "rgb(79, 129, 189)"};
const s_ranges_spacing={"min-width": "1em", "display": "inline-block"};

const color_odd="#FFE0FF";
const color_even="#E0FFFF";

//const color_taken="#EEEEEE";
const color_taken="#FFFFCC";
const color_table_buttons="rgb(79, 129, 189)";

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

$.fn.range_symbol = function(net_start, net_last, range_start, range_stop) {
  if(net_start == range_start && net_last > range_stop) {
    this.html("&#x21f1;")  // ⇱ , range is started on row net and goes inside row
     .css({"font-weight": "bold"})
  } else if(net_start == range_start && net_last < range_stop) {
    this.html("&#x2533;"); // ┳ , range is started on row net and goes to next row or beyond
  } else if(net_start < range_start && net_last < range_stop && net_last >= range_start) {
    this.html("&#x250f;"); // ┏ , range is started inside row net and goes to next row or beyond
  } else if(net_start > range_start && net_last < range_stop) {
    this.html("&#x2503;"); // ┃, row net is inside range
  } else if(net_start < range_start && net_last > range_stop) {
    this.html("&#x25c0;"); // ◀, range is inside row net
  } else if(net_start == range_start && net_last == range_stop) {
    //this.html("&#x21b9;")  // ↹
    // .css({"transform": "rotate(90deg)"}); // , range is equal row net
    //this.html("&#x29f1;"); // ⧱ , range is equal row net
    this.html("&#x25fc;"); // ◼ , range is equal row net
  } else if(net_start > range_start && net_start <= range_stop && net_last > range_stop) {
    this.html("&#x2517;"); // ┗ , range is started before row net and goes inside row
  } else if(net_start > range_start && net_last == range_stop) {
    this.html("&#x253B;"); // ┻ , range is started before row net and end on row
  } else if(net_start < range_start && net_last == range_stop) {
    this.html("&#x21f2;")  // ⇲ , range is started inside row net and ends on row
     .css({"font-weight": "bold"})
  } else {
    this.html("?"); //unpredicted
  };
  
  return this;
};

function saveQuery(title) {
  let query_string="";
  let ks=keys($R).sort();
  for(let k=0; k < ks.length; k++) {
    let key=ks[k];
    if(typeof($R[key]) === "object") {
      for(let i=0; i < $R[key].length; i++) {
        if(query_string.length > 0) query_string += "&";
        query_string += key+"[]="+encodeURIComponent($R[key][i]);
      };
    } else {
      if(typeof($R[key]) === "boolean") {
        if($R[key] === true) {
          if(query_string.length > 0) query_string += "&";
          query_string += key;
        };
      } else {
        if(query_string.length > 0) query_string += "&";
        query_string += key+"="+encodeURIComponent($R[key]);
      };
    };
  };
  let save_uri=page_root;
  if(query_string.length > 0) {
    save_uri += "?"+query_string;
  };
  if(window.location.href != save_uri) {
    window.history.pushState($R, title, save_uri);
  };
};

function v4oct2long(i3, i2, i1, i0) {
  let ret = Number(i3) * 16777216;
  ret += Number(i2) * 65536;
  ret += Number(i1) * 256;
  ret += Number(i0);
  return ret >>> 0;
};

function v4ip2long(ip) {
  let m=String(ip).match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if(m == null || m.length != 5 || Number(m[1]) > 255 || Number(m[2]) > 255 || Number(m[3]) > 255 || Number(m[4]) > 255) {
    return false;
  } else {
    return(v4oct2long(m[1], m[2], m[3], m[4]));
  };
};

/*
function v4oct2long(i3, i2, i1, i0) {
  let ret = (0xFF & i3) << 24;
  ret += (0xFF & i2) << 16;
  ret += (0xFF & i1) << 8;
  ret += (0xFF & i0);
  return ret >>> 0;
};
*/
function has_right(right, rightstr) {
  if(rightstr === undefined) { rightstr=ud['user']['rights']; };
  if(rightstr.indexOf(R_SUPER) >= 0 || rightstr.indexOf(right) >= 0) {
    return true;
  } else {
    return false;
  };
};

function v4long2ip(net) {
  let o=ip4octets(net);
  return o[0]+"."+o[1]+"."+o[2]+"."+o[3];
};

function ip4octets(net) {
  net = Number(net);
  let ret=[];
  ret[0] = Math.floor( net / 16777216);
  ret[1] = Math.floor( (net & 0xFFFFFF) / 65536);
  ret[2] = Math.floor( (net & 0xFFFF) / 256);
  ret[3] = net & 0xFF;
  return ret;
};

/*
function ip4octets(net) {
  let ret=[];
  ret[0] = net >>> 24;
  ret[1] = (net >>> 16) & 0xFF;
  ret[2] = (net >>> 8) & 0xFF;
  ret[3] = net & 0xFF;
  return ret;
};
*/

function clear_calc() {
  $(".calc_highlight").each(function() {
    let saved_bg_color=$(this).data("saved_bg_color");

    $(this).removeClass("calc_highlight");
    if(saved_bg_color != undefined) {
      $(this).css({"background-color": saved_bg_color});
    } else {
      $(this).css({"background-color": "initial"});
    };
  });

  $("#calc_text").empty();
};

function validate_json(j) {
  try {
    JSON.parse(j);
    return true;
  } catch(e) {
    return false;
  };
};

function validate_json_elm(animate_good, animate_bad) {
  let j=$(this).val();
  if(validate_json(j)) {
    if(animate_good != undefined) $(this).animateHighlight(animate_good, 200);
    return true;
  } else {
    if(animate_bad != undefined) $(this).animateHighlight(animate_bad, 200);
    return false;
  };
};

function validate_v4range() {
  let start_input=$("INPUT#v4range_start");
  let stop_input=$("INPUT#v4range_stop");

  if(start_input.length != 1 || stop_input.length != 1) { error_at(); return false; };

  let start_ip=start_input.val();
  let stop_ip=stop_input.val();

  let start_long=v4ip2long(start_ip);
  let stop_long=v4ip2long(stop_ip);
  
  let valid=true;

  if(start_long === false) {
    start_input.animateHighlight(); valid=false;
  };
  if(stop_long === false) {
    stop_input.animateHighlight(); valid=false;
  };

  if(valid && (start_long > stop_long)) {
    start_input.add(stop_input).animateHighlight(); valid=false;
  };

  return valid;
};

function user_state_elm(user) {
  let state_icon;
  let state_text;
  let state_color;

  if(Number(user['user_state']) == 1) {
    state_icon="ui-icon-circle-check";
    state_text="Пользователь включен";
    state_color="green";
  } else if(Number(user['user_state']) == 0) {
    state_icon="ui-icon-locked";
    state_text="Пользователь отключен";
    state_color="dimgray";
  } else if(Number(user['user_state']) == -1) {
    state_icon="ui-icon-circle-plus";
    state_text="Пользователь добавлен автоматически. Требуется активация.";
    state_color="magenta";
  } else if(Number(user['user_state']) == -2) {
    state_icon="ui-icon-eye";
    state_text="Пользователь отключен и скрыт.";
    state_color="tomato";
  } else {
    state_icon="ui-icon-circle-help";
    state_text="Неизвестный статус!.";
    state_color="red";
  };

  if(Number(user['ap_off']) != 0) {
    state_text += "\nОтключена служба авторизации для этого пользователя.";
    state_color="gray";
  };

  return $(LABEL).addClass("ui-icon").addClass(state_icon).css({"color": state_color}).title(state_text).data("text", state_text);
};

function user_edit(user_id, opt, donefunc) {
  if(user_id == undefined) { error_at(); return; };;

  if( $("#user_edit"+user_id).length != 0) { return; };

  let dialog=$(DIV).id("user_edit"+user_id)
   .data("opt", opt)
   .addClass("dialog_start")
   .title(has_right(R_SUPER)?"Редактирование пользователя":"Просмотр пользователя")
   .css({"white-space": "pre", "font-size": "larger"})
   .appendTo("BODY")
  ;

  if(_debug_opts) {
    dialog.append( $(LABEL).addClass("ui-icon").addClass("ui-icon-info").css({"position": "absolute", "display": "inline-block", "color": "lightgray", "left": "0.2em"}).title(jstr(opt)) );
  };

  let d={
    modal:true,
    maxHeight:1000,
    maxWidth:1000,
    minWidth:600,
    minHeight:500,
    //width: "auto",
    buttons: [],
    close: function() {
      $(this).dialog("destroy");
      $(this).remove();
    },
  };

  if(has_right(R_SUPER)) {
    d['buttons'].push({ "text": "Сохранить", "class": "confirm_btn", "click": function() {
      $(this).dialog( "close" ); 
      let ret;
      if(donefunc != undefined) donefunc(ret);
    }});
  };

  d['buttons'].push({ "text": has_right(R_SUPER)?"Отменить":"Закрыть", "click": function() { $(this).dialog( "close" ); } });

  let table=$(TABLE)
   .append( $(TR)
     .append( $(TD).css({"text-align": "right", "padding-right": "1em"})
       .text("Имя:")
     )
     .append( $(TD)
       .append( $(LABEL).addClass("user_name")
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right", "padding-right": "1em"})
       .text("Логин:")
     )
     .append( $(TD)
       .append( $(LABEL).addClass("user_username")
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right", "padding-right": "1em"})
       .text("Служба авторизации:")
     )
     .append( $(TD)
       .append( $(LABEL).addClass("ap_state")
         .addClass("ui-icon")
         .css({"marin-left": "0.3em", "margin-right": "0.3em"})
       )
       .append( $(LABEL).addClass("ap_name")
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right", "padding-right": "1em"})
       .text("Крайний вход:")
     )
     .append( $(TD)
       .append( $(LABEL).addClass("user_last_login")
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right", "padding-right": "1em"})
       .text("E-mail:")
     )
     .append( $(TD)
       .append( $(LABEL).addClass("user_email")
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right", "padding-right": "1em"})
       .text("Телефон:")
     )
     .append( $(TD)
       .append( $(LABEL).addClass("user_phone")
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right", "padding-right": "1em"})
       .text("OpenId sub:")
     )
     .append( $(TD)
       .append( $(LABEL).addClass("user_sub")
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right", "vertical-align": "top", "padding-right": "1em"})
       .text("Состояние:")
     )
     .append( $(TD).addClass("states_list").css({"font-size": "small", "vertical-align": "top"})
       .append( $(TABLE)
         .append( $(TR)
           .append( $(TD)
             .append( user_state_elm({"user_state": 1, "ap_off": 0})
             )
             .append( $(LABEL).prop("for", "state_on")
               .css({"margin-bottom": "0.4em", "margin-right": "0.3em"})
               .text("Включен")
               .title("Пользователь включен.")
             )
             .append( $(INPUT).prop({"name": "state", "id": "state_on", "type": "radio"})
             )
           )
           .append( $(TD)
             .append( user_state_elm({"user_state": 0, "ap_off": 0})
             )
             .append( $(LABEL).prop("for", "state_off")
               .css({"margin-bottom": "0.4em", "margin-right": "0.3em"})
               .text("Отключен")
               .title("Пользователь отключен.")
             )
             .append( $(INPUT).prop({"name": "state", "id": "state_off", "type": "radio"})
             )
           )
         )
         .append( $(TR)
           .append( $(TD)
             .append( user_state_elm({"user_state": -1, "ap_off": 0})
             )
             .append( $(LABEL).prop("for", "state_added")
               .css({"margin-bottom": "0.4em", "margin-right": "0.3em"})
               .text("Авт.Доб.")
               .title("Пользователь добавлен автоматически и требует активации.")
             )
             .append( $(INPUT).prop({"name": "state", "id": "state_added", "type": "radio"})
             )
           )
           .append( $(TD)
             .append( user_state_elm({"user_state": -2, "ap_off": 0})
             )
             .append( $(LABEL).prop("for", "state_del")
               .css({"margin-bottom": "0.4em", "margin-right": "0.3em"})
               .text("Скрыт")
               .title("Пользователь отключен и скрыт.")
             )
             .append( $(INPUT).prop({"name": "state", "id": "state_del", "type": "radio"})
             )
           )
         )
       )
     )
   )
  ;

  table.appendTo(dialog);

  dialog
   .append( $(DIV)
     .append( $(LABEL).text("Группы пользователя: ")
     )
     .append( (opt == undefined || !opt['allow_groups_change'] || !has_right(R_SUPER)) ? $(LABEL) : $(LABEL)
       .addClass("ui-icon").addClass("ui-icon-plusthick").addClass("ui-button")
       .css({"color": "green"})
       .title("Добавить в группу")
       .click(function() {
         let _cont=$(this).closest(".dialog_start").find(".groups_list");
         let exclude_list=Array();

         _cont.find(".groups_list_row").each(function() {
           let _data=$(this).data("data");
           exclude_list.push( _data['group_id'] );
         });

         groups_list([], exclude_list, { "return": "many", 'allow_user_info_btn': false }, function(ret_data) {
           for(let i=0; i < ret_data.length; i++) {
             let group=ret_data[i];
             group['_minus'] = true;
             group['_sel'] = undefined;
             group['_no_user_info_btn'] = true;
             let row=groups_list_row(group);
             row.appendTo( _cont );
           };
         });
       })
     )
     .append( (opt == undefined || !opt['allow_groups_change'] || !has_right(R_SUPER)) ? $(LABEL) : $(LABEL)
       .addClass("ui-icon").addClass("ui-icon-arrowrefresh-1-s").addClass("ui-button")
       .css({"color": color_table_buttons, "margin-left": "0.5em" })
       .title("Восстановить начальный список")
       .click(function() {
         let _cont=$(this).closest(".dialog_start").find(".groups_list");
         let prev_list=_cont.data("redo_data");
         if(prev_list == undefined) { error_at(); return; };

         _cont.empty();

         for(let i=0; i < prev_list.length; i++) {
           let group=prev_list[i];
           let row=groups_list_row(group);
           row.appendTo( _cont );
         };

       })
     )
   )
  ;

  let groups_table=$(TABLE).addClass("groups_list")
   .appendTo( dialog )
  ;

  table.find("INPUT").checkboxradio({"disabled": !has_right(R_SUPER) || user_id == ud['user']['user_id']});

  run_query({"action": "get_user", "user_id": user_id}, function(data) {
    table.find(".user_name").text(data['ok']['user_name']);
    table.find(".user_username").text(data['ok']['user_username']);
    table.find(".ap_name").text(data['ok']['ap_name']);
    if(Number(data['ok']['ap_off']) != 0) {
      table.find(".ap_state").addClass("ui-icon-alert")
       .title("Служба авторизации отключена")
       .css({"color": "red"})
      ;
    } else {
      table.find(".ap_state").addClass("ui-icon-check")
       .title("Служба авторизации включена")
       .css({"color": "green"})
      ;
    };
    table.find(".user_email").text(data['ok']['user_email']);
    table.find(".user_phone").text(data['ok']['user_phone']);
    table.find(".user_sub").text(data['ok']['user_sub']);
    table.find(".user_last_login").text(data['ok']['user_last_login']);

    switch(Number(data['ok']['user_state'])) {
    case 1:
      table.find(".states_list").find("#state_on").prop("checked", true);
      break;
    case 0:
      table.find(".states_list").find("#state_off").prop("checked", true);
      break;
    case -1:
      table.find(".states_list").find("#state_added").prop("checked", true);
      break;
    case -2:
      table.find(".states_list").find("#state_del").prop("checked", true);
      break;
    default:
      error_at();
    };

    table.find(".states_list").find("INPUT").checkboxradio("refresh");

    for(let i=0; i < data['ok']['user_groups'].length; i++) {
      data['ok']['user_groups'][i]['_no_user_info_btn'] = true;
      if(has_right(R_SUPER) && opt != undefined && opt['allow_groups_change']) {
        data['ok']['user_groups'][i]['_minus'] = true;
      };
    };

    for(let i=0; i < data['ok']['user_groups'].length; i++) {
      let group=data['ok']['user_groups'][i];
      let row=groups_list_row(group);
      row.appendTo( groups_table );
    };
    
    groups_table.data("redo_data", data['ok']['user_groups']);
  });

  dialog.dialog(d);
};

function get_users_list_row(user) {
  let ret=$(DIV).addClass("user_list_row")
   .data("data", user)
   .css({"display": "table-row", "white-space": "pre"})
  ;

  if(_debug_opts) {
    ret
     .append( $(DIV).css({"display": "table-cell"})
       .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-info").css({"color": "lightgray", "font-size": "xx-small"})
         .title(jstr(user))
       )
     )
   ;
  };

  if(user['_show_minus']) {
    ret
     .append( $(DIV).css({"display": "table-cell"})
       .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-minusthick").addClass("ui-button")
         .css({"color": "coral"})
         .title("Убрать из списка")
         .click(function() {
           let _cont=$(this).closest(".user_list_row").parent();
           $(this).closest(".user_list_row").remove();
           _cont.trigger("list_change");
         })
       )
     )
    ;
  } else if(user['_sel'] == "multi") {
    ret
     .append( $(DIV).css({"display": "table-cell"})
       .append( $(INPUT).addClass("select_checkbox")
         .prop({"type": "checkbox"})
         .on("change", function() {
           $(this).closest(".user_list_row").parent().trigger("sel_change");
         })
       )
     )
    ;
  };

  let state_elm=user_state_elm(user);

  ret
   .append( $(DIV).css({"display": "table-cell"})
     .append( state_elm.css({"margin-left": "0.3em"}) )
   )
  ;

  let text_color="black";
  let text_title=user['user_username']+" @ "+user['ap_name'];

  if(Number(user['ap_off']) != 0) {
    text_color="gray";
    text_title += "\nОтключена служба авторизации для этого пользователя.";
  };

  ret
   .append( $(DIV).css({"display": "table-cell"})
     .append( $(SPAN).text(user['user_name'])
       .title(text_title)
       .css({"color": text_color, "margin-left": "0.3em"})
     )
   )
  ;

  if(user['_show_info_btn']) {
    ret
     .append( $(DIV).css({"display": "table-cell"})
       .append( $(LABEL).addClass("ui-icon").addClass('ui-icon-bullets').addClass("ui-button")
         .css({"color": color_table_buttons, "margin-left": "0.3em"})
         .title("Свойства пользователя")
         .click(function() {
           let row=$(this).closest(".user_list_row");
           let _cont=row.parent();
           let _data=row.data("data");
           user_edit(_data['user_id'], { "allow_groups_change": _data['_allow_groups_change'] }, function(ret_data) {
             ret_data['_show_minus'] = _data['_show_minus'];
             ret_data['_allow_groups_change'] = _data['_allow_groups_change'];
             row.replaceWith( get_users_list_row(ret_data) );
             _cont.trigger("list_change");
           });
         })
       )
     )
    ;
  };

  if(Number(user['user_state']) < -1 || Number(user['ap_off']) != 0) {
    ret.addClass('hide');
  };

  return ret;
};

function users_list(exclude_list, opt, donefunc) {
  if(!has_right(R_VIEWANY)) { error_at(); return; };

  if( $("#users_list").length != 0) { error_at(); return; };

  let dialog=$(DIV).id("users_list")
   .data("opt", opt)
   .addClass("dialog_start")
   .title("Пользователи")
   .css({"white-space": "pre", "font-size": "larger"})
   .appendTo("BODY")
  ;

  if(_debug_opts) {
    dialog.append( $(LABEL).addClass("ui-icon").addClass("ui-icon-info").css({"position": "absolute", "display": "inline-block", "color": "lightgray", "left": "0.2em"}).title(jstr(opt)) );
  };

  let d={
    modal:true,
    maxHeight:1000,
    maxWidth:1000,
    minWidth:600,
    minHeight:500,
    //width: "auto",
    buttons: [],
    close: function() {
      $(this).dialog("destroy");
      $(this).remove();
    },
    open: function() {
      $(this).dialog("widget").find("BUTTON.confirm_btn").prop("disabled", true).css({"color": "gray"});
    }
  };

  if(donefunc != undefined) {
    d['buttons'].push({ "text": "Подтвердить", "class": "confirm_btn", "click": function() {
      let ret=Array();

      $(this).find(".users_list").find(".user_list_row").each(function() {
         if($(this).find("INPUT.select_checkbox").is(":checked")) {
           ret.push( $(this).data("data") );
         };
      });

      if(ret.length == 0) return;

      $(this).dialog( "close" ); 
      donefunc(ret);
    }});
  };

  d['buttons'].push({ "text": "Закрыть", "click": function() {$(this).dialog( "close" ); } });

  let table=$(DIV).css({"display": "table"}).addClass("users_list");

  if(donefunc != undefined) {
    table
     .on("sel_change", function() {
       let sel_count=0;
       $(this).find(".user_list_row").each(function() {
         if($(this).find("INPUT.select_checkbox").is(":checked")) sel_count++;
       });
       $(this).closest(".dialog_start").dialog("widget").find("BUTTON.confirm_btn").prop("disabled", sel_count == 0).css({"color": sel_count == 0?"gray":"black"});
     })
    ;
  };

  table.appendTo(dialog);

  dialog.dialog(d);

  run_query({"action": "get_users"}, function(data) {

    data['ok'].sort(function(a, b) {
      if(a['user_state'] != b['user_state']) {
        return Number(b['user_state']) - Number(a['user_state']);
      } else {
        return String(a['user_name']).localeCompare(String(b['user_name']));
      };
    });

    for(let i=0; i < data['ok'].length; i++) {
      let user=data['ok'][i];
      if(in_array(exclude_list, user['user_id'])) continue;

      if(opt != undefined && opt['show_sel'] != undefined) {
        user['_sel'] = opt['show_sel'];
      };

      user['_show_info_btn'] = (opt != undefined && opt['allow_user_info_btn']);
      user['_allow_groups_change'] = (opt != undefined && opt['allow_user_group_change']);
      //user['_allow_edit'] = (opt != undefined && opt['allow_edit']);

      let row=get_users_list_row(user);
      row.appendTo( table );
    };
  });
};

function group_edit(group_id, opt, donefunc) {
  if(group_id == undefined && !has_right(R_SUPER)) { error_at(); return; };

  let id="group_edit";
  if(group_id != undefined) { id += group_id; };

  if( $("#"+id).length != 0) { return; };

  let allow_group_edit = opt != undefined && opt['allow_edit'];

  let dialog=$(DIV).id(id)
   .data("opt", opt)
   .addClass("dialog_start")
   .title(group_id == undefined?"Создание группы":(has_right(R_SUPER) && allow_group_edit ?"Редактирование группы":"Просмотр группы"))
   .css({"white-space": "pre", "font-size": "larger"})
   .appendTo("BODY")
  ;

  if(_debug_opts) {
    dialog.append( $(LABEL).addClass("ui-icon").addClass("ui-icon-info").css({"position": "absolute", "display": "inline-block", "color": "lightgray", "left": "0.2em"}).title(jstr(opt)) );
  };

  let d={
    modal:true,
    maxHeight:1000,
    maxWidth:1000,
    minWidth:600,
    minHeight:500,
    //width: "auto",
    buttons: [],
    close: function() {
      $(this).dialog("destroy");
      $(this).remove();
    },
  };

  if(group_id == undefined || (has_right(R_SUPER) && allow_group_edit)) {
    d['buttons'].push({ "text": (group_id == undefined)?"Создать":"Сохранить", "class": "confirm_btn", "click": function() {
      $(this).dialog( "close" ); 
      let ret;
      if(donefunc != undefined) donefunc(ret);
    }});
  };

  d['buttons'].push({ "text": (group_id == undefined || (has_right(R_SUPER) && allow_group_edit))?"Отменить":"Закрыть", "click": function() { $(this).dialog( "close" ); } });

  let table=$(TABLE)
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .text("Имя группы:")
     )
     .append( $(TD) )
     .append( $(TD)
       .append( $(INPUT).addClass("group_name")
         .prop({"readonly": !has_right(R_SUPER) || !allow_group_edit})
       )
       .append( $(LABEL).addClass("group_default").css({"margin-left": "0.5em"}) )
     )
   )
  ;

  let r_td=$(TD).addClass("group_rights");

  for(let i=0; i < group_rights.length; i++) {
    r_td
     .append( $(LABEL).text(group_rights[i]['label_text'])
       .addClass("right")
       .addClass("right_"+group_rights[i]['right'])
       .data("right", group_rights[i]['right'])
       .title( group_rights[i]['label_descr'] )
       .css({"background-color": "lightgray", "color": "gray", "border": "1px solid gray", "margin-right": "0.3em", "font-size": "smaller"})
       .click( (!has_right(R_SUPER) || !allow_group_edit)?function() {} : function() {
         if($(this).hasClass("on")) {
           $(this).removeClass("on").css({"background-color": "lightgray", "color": "gray"});
         } else {
           $(this).addClass("on").css({"background-color": "lightgreen", "color": "black"});
         };
       })
     )
    ;
  };

  if(group_id != undefined && has_right(R_SUPER) && allow_group_edit) {
    r_td
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-arrowrefresh-1-s").addClass("ui-button")
       .css({"padding-left": "0.2em", "padding-right": "0.2em", "margin-left": "0.5em", "color": color_table_buttons})
       .title("Вернуть права к первоначальному виду")
       .click(function() {
         $(this).closest(".dialog_start").find(".right").each(function() {
           if($(this).data("save_value") === true) {
             $(this).addClass("on").css({"background-color": "lightgreen", "color": "black"});
           } else if($(this).data("save_value") === false) {
             $(this).removeClass("on").css({"background-color": "lightgray", "color": "gray"});
           };
         })
       })
     )
    ;
  };

  table
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .text("Права:")
     )
     .append( $(TD) )
     .append( r_td )
   )
  ;

  table
   .append( $(TR)
     .append( $(TD).css({"text-align": "right", "vertical-align": "top"})
       .text("Пользователи:")
     )
     .append( $(TD).css({"vertical-align": "top"})
       .append( (!has_right(R_SUPER) || !allow_group_edit)?$(LABEL):$(LABEL).addClass("ui-icon").addClass("ui-icon-plusthick").addClass("ui-button")
         .css({"padding-left": "0.2em", "padding-right": "0.2em", "margin-left": "0.5em", "color": color_table_buttons})
         .title("Добавить пользователя в группу")
         .click(function() {
           let _opt=$(this).closest(".dialog_start").data("opt");
           let exclude_list=Array();
           let _cont=$(this).closest(".dialog_start").find(".users_list");
           _cont.find(".user_list_row").each(function() {
             let _data=$(this).data("data");
             exclude_list.push(_data['user_id']);
           });
           users_list(exclude_list, {'show_sel': "multi", 'allow_user_info_btn': true, 'allow_user_group_change': false }, function(ret_data) {
             for(let i=0; i < ret_data.length; i++) {
               ret_data[i]['_allow_groups_change'] = false;
               ret_data[i]['_show_minus'] = true;
               ret_data[i]['_show_info_btn'] = (_opt == undefined || _opt['allow_user_info_btn']);
               _cont.append( get_users_list_row( ret_data[i] ) );
             };
             _cont.trigger("list_change");
           });
         })
       )
       .append( $(BR) )
       .append( (!has_right(R_SUPER) || !allow_group_edit)?$(LABEL):$(LABEL).addClass("ui-icon").addClass("ui-icon-arrowrefresh-1-s").addClass("ui-button")
         .css({"padding-left": "0.2em", "padding-right": "0.2em", "margin-left": "0.5em", "color": color_table_buttons})
         .title("Вернуть перечень пользователей к первоначальному виду")
         .click(function() {
           let _cont=$(this).closest(".dialog_start").find(".users_list");
           let _initial_list=_cont.data("redo_data");
           if(_initial_list == undefined) { error_at(); return; };

           _cont.empty();

           for(let i=0; i < _initial_list.length; i++) {
             _cont.append( get_users_list_row( _initial_list[i] ) );
           };

           _cont.trigger("list_change");
         })
       )
       .append( $(BR) )
       .append( !has_right(R_SUPER)?$(LABEL):$(LABEL).addClass("ui-icon").addClass("ui-icon-eye").addClass("ui-button")
         .addClass("show_deleted")
         .css({"padding-left": "0.2em", "padding-right": "0.2em", "margin-left": "0.5em", "color": color_table_buttons})
         .title("Показать скрытых пользователей")
         .click(function() {
           let _cont=$(this).closest(".dialog_start").find(".users_list");
           if($(this).hasClass("on")) {
             $(this).removeClass("on").css({"color": color_table_buttons}).title("Показать скрытых пользователей");
           } else {
             $(this).addClass("on").css({"color": "coral"}).title("Не показывать скрытых пользователей");
           };
           _cont.trigger("list_change");
         })
       )
     )
     .append( $(TD).css({"vertical-align": "top"})
       .append( $(DIV).addClass("users_list")
         .on("list_change", function() {
           let to_hide=$(this).find(".hide");
           let eye=$(this).closest(".dialog_start").find(".show_deleted");
           if(to_hide.length == 0) {
             eye.hide();
           } else {
             eye.show();
           };
           let show_deleted=eye.hasClass("on");
           to_hide.toggle(show_deleted);
         })
       )
     )
   )
  ;

  table.appendTo(dialog);

  if(group_id != undefined) {
    run_query({"action": "get_group", "group_id": group_id}, function(data) {
      table.find("INPUT.group_name").val(data['ok']['group_name']);
      if( data['ok']['group_name'] == 'default' || Number(data['ok']['group_default']) == 1 ) {
        table.find("INPUT.group_name").prop("readonly", true).title("Запрещается переименовывать группу по умолчанию.");
        table
         .find(".group_default").append( $(LABEL).addClass("ui-icon").addClass("ui-icon-locked")
           .css({"padding-left": "0.2em", "padding-right": "0.2em", "margin-left": "0.5em"})
           .title("Группа по умолчанию. Автоматически назначается пользователям без группы и вновь регистрирующимся.")
         )
        ;
      };
      for(let i=0; i < group_rights.length; i++) {
        if(String(data['ok']['group_rights']).indexOf( group_rights[i]['right'] ) >= 0 ) {
          table.find(".right_"+group_rights[i]['right']).addClass("on").css({"background-color": "lightgreen", "color": "black"}).data("save_value", true);
        } else {
          table.find(".right_"+group_rights[i]['right']).data("save_value", false);
        };
      };

      let users_div=table.find(".users_list");

      for(let i=0; i < data['ok']['group_users'].length; i++) {
        data['ok']['group_users'][i]['_allow_groups_change'] = false;
        if(has_right(R_SUPER) && allow_group_edit) {
          data['ok']['group_users'][i]['_show_minus'] = true;
        };

        data['ok']['group_users'][i]['_show_info_btn'] = (opt == undefined || opt['allow_user_info_btn']);
      };

      for(let i=0; i < data['ok']['group_users'].length; i++) {
        let user=data['ok']['group_users'][i];
        let row=get_users_list_row(user);
        users_div.append( row );
      };

      users_div
       .data("redo_data", data['ok']['group_users'])
       .trigger("list_change")
      ;
    });
  };

  dialog.dialog(d);
};

function groups_list_row(group, donefunc) {
  let ret=$(TR).addClass("groups_list_row")
   .data("data", group)
   .css({"background-color": group['_presel']?"paleturquoise":"white"})
   .css({"margin-top": "0.3em"})
  ;
  let sel_td=$(TD)
   .css({"padding-right": "0.5em"})
   .appendTo( ret )
  ;

  if(_debug_opts) {
    sel_td
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-info").css({"color": "lightgray", "font-size": "xx-small", "margin-right": "0.1em"})
       .title(jstr(group))
     )
   ;
  };

  if(group['_sel'] == 'one') {
    if(donefunc != undefined) {
      sel_td
       .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-select").addClass("ui-button")
         .title("Выбрать эту группу и вернуться на предыдущий экран")
         .click(function() {
           let data=$(this).closest("TR").data("data");
           $(this).closest(".dialog_start").dialog("close");
           donefunc(data);
         })
       )
      ;
    } else {
      sel_td
       .append( $(LABEL).addClass("ui-icon").addClass(group['_presel']?"ui-icon-check":"ui-icon-blank").addClass("ui-button")
         .title(group['_presel']?"Эта группа выбрана":"")
       )
      ;
    };
  } else if(group['_sel'] != undefined) {
    sel_td
     .append( $(INPUT).prop({"type": "checkbox", "checked": group['_presel']})
       .addClass("select_checkbox")
       .click(function() { return donefunc != undefined; })
       .on("change", function() {
         $(this).closest("TABLE").trigger("sel_change");
       })
     )
    ;
  } else if(group['_minus']) {
    sel_td
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-minusthick").addClass("ui-button")
       .css({"color": "coral"})
       .title("Удалить из списка")
       .click(function() {
         let row=$(this).closest("TR");
         let _cont=row.closest("TABLE");
         row.remove();
         _cont.trigger("list_change");
       })
     )
    ;
  };

  let r_td=$(TD)
   .css({"padding-right": "0.5em"})
   .appendTo(ret)
  ;

  for(let i=0; i < group_rights.length; i++) {
    if(String(group['group_rights']).indexOf( group_rights[i]['right'] ) >= 0) {
      r_td
       .append( $(LABEL).text(group_rights[i]['label_text'])
         .title( group_rights[i]['label_descr'] )
         .css({"background-color": "lightgreen", "border": "1px solid gray", "margin-right": "0.3em", "font-size": "smaller"})
       )
      ;
    };
  };

  let m_td=$(TD)
   //.css({"padding-right": "0.5em"})
   .append( $(LABEL).addClass("ui-icon").addClass( in_array(ud['user']['groups'].split(","), group['group_id'])?"ui-icon-user":"ui-icon-blank")
     .title(in_array(ud['user']['groups'].split(","), group['group_id'])?"Вы входите в эту группу":"")
   )
   .appendTo(ret)
  ;

  ret
   .append( $(TD).text(group['group_name'])
   )
  ;

  ret
   .append( $(TD).text(group['users_count'])
     .title("Пользователей в группе")
     .css({"padding-left": "0.3em"})
   )
  ;

  ret
   .append( $(TD)
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-bullets").addClass("ui-button")
       .title((has_right(R_SUPER) && group['_allow_edit'])?"Редактирование группы":"Просмотр группы")
       .css({"padding-left": "0.2em", "padding-right": "0.2em", "margin-left": "0.5em", "color": color_table_buttons})
       .click(function() {
         let row=$(this).closest(".groups_list_row");
         let prev_data=row.data("data");
         group_edit(prev_data['group_id'], { "allow_edit": prev_data['_allow_edit'], "allow_user_info_btn": !prev_data['_no_user_info_btn'] }, function(ret_data) {
           //copy '_xxx' keys from prev_data
           alert(jstr(ret_data));
         });
       })
     )
   )
  ;

  return ret;
};

function groups_list(select_gr_ids, exclude_list, opt, donefunc) {
  if( $("#groups_list").length != 0) { error_at(); return; };

  let presel_list;
  if(typeof(select_gr_ids) == "object") {
    presel_list = select_gr_ids;
  } else {
    presel_list = [select_gr_ids];
  };

  let dialog=$(DIV).id("groups_list")
   .data("opt", opt)
   .addClass("dialog_start")
   .title("Группы пользователей")
   .css({"white-space": "pre", "font-size": "larger"})
   .appendTo("BODY")
  ;

  if(_debug_opts) {
    dialog.append( $(LABEL).addClass("ui-icon").addClass("ui-icon-info").css({"position": "absolute", "display": "inline-block", "color": "lightgray", "left": "0.2em"}).title(jstr(opt)) );
  };

  let d={
    modal:true,
    maxHeight:1000,
    maxWidth:1000,
    minWidth:600,
    minHeight:500,
    //width: "auto",
    buttons: [],
    close: function() {
      $(this).dialog("destroy");
      $(this).remove();
    },
    open: function() {
      if(opt != undefined && opt['return'] == "many" && donefunc != undefined && presel_list.length == 0) {
        $(this).dialog("widget").find("BUTTON.confirm_btn").prop("disabled", true).css({"color": "gray"});
      };
    }
  };

  if(opt != undefined && (opt['return'] == "any" || opt['return'] == "many") && donefunc != undefined) {
    d['buttons'].push({ "text": "Подтвердить", "class": "confirm_btn", "click": function() {
      let ret=Array();

      $(this).find("TABLE").find("TBODY").find(".groups_list_row").each(function() {
         if($(this).find("INPUT.select_checkbox").is(":checked")) {
           ret.push( $(this).data("data") );
         };
      });

      if(ret.length == 0 && opt['return'] == "many") return;

      $(this).dialog( "close" ); 
      donefunc(ret);
    }});
  };

  d['buttons'].push({ "text": "Закрыть", "click": function() {$(this).dialog( "close" ); } });

  let table=$(TABLE);

  if(opt != undefined && opt['return'] == "many" && donefunc != undefined) {
    table
     .on("sel_change", function() {
       let sel_count=0;
       $(this).find("TBODY").find(".groups_list_row").each(function() {
         if($(this).find("INPUT.select_checkbox").is(":checked")) sel_count++;
       });
       $(this).closest(".dialog_start").dialog("widget").find("BUTTON.confirm_btn").prop("disabled", sel_count == 0).css({"color": sel_count == 0?"gray":"black"});
     })
    ;
  };

  if(has_right(R_SUPER) && opt != undefined && opt['allow_add']) {
    table
     .append( $(THEAD)
       .append( $(TR)
         .append( $(TD)
           .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-plusthick").addClass("ui-button")
             .css({"color": "green"})
             .click(function() {
             })
           )
         )
         .append( $(TD).prop("colspan", 99) )
       )
     )
    ;
  };

  let tbody=$(TBODY)
   .appendTo( table )
  ;

  table.appendTo(dialog);

  dialog.dialog(d);

  run_query({"action": "get_groups"}, function(data) {
    for(let i=0; i < data['ok'].length; i++) {
      let check=in_array(presel_list, data['ok'][i]['group_id']);
      data['ok'][i]['_presel'] = check;
    };

    data['ok'].sort(function(a, b) {
      if(a['_presel'] != b['_presel']) {
        if(a['_presel']) { return -1; } else { return 1; };
      } else {
        return String(a['group_name']).localeCompare(String(b['group_name']));
      };
    });

    for(let i=0; i < data['ok'].length; i++) {
      let group=data['ok'][i];
      if(in_array(exclude_list, group['group_id'])) continue;

      if(opt != undefined && opt['return'] == "one") {
        group['_sel'] = "one";
      } else if(opt != undefined && opt['return'] != undefined) {
        group['_sel'] = "multi";
      };

      group['_no_user_info_btn'] = (opt != undefined && opt['allow_user_info_btn'] === false);
      group['_allow_edit'] = (opt != undefined && opt['allow_edit']);

      let row=groups_list_row(group, donefunc);
      row.appendTo( tbody );
    };
  });
};

function group_net_right_div(gr, mask, opt) {
  let ret=$(DIV)
   .css({"white-space": "pre", "margin-bottom": "0.2em"})
   .addClass("group_rights_div")
  ;

  if(_debug_opts) {
    dialog.append( $(LABEL).addClass("ui-icon").addClass("ui-icon-info").css({"position": "absolute", "display": "inline-block", "color": "lightgray", "left": "0.2em"}).title(jstr(opt)) );
  };

  if(gr == undefined) {
    ret.css({"background-color": "yellow"});
  };

  let rigths_span=$(SPAN);

  for(let i=0; i < group_net_rights.length; i++) {
    if(((group_net_rights[i]['right'] & mask) >>> 0) > 0) {
      let is_set = (gr != undefined && ((Number(gr['rmask']) & group_net_rights[i]['right']) >>> 0) > 0);
      if(is_set || (opt != undefined && opt['allow_edit'] == true)) {
        let r_label=$(LABEL).addClass("right")
         .toggle(is_set || gr == undefined)
         .css({"border": "1px solid gray", "padding-left": "0.1em", "padding-right": "0.1em", "margin-left": "0.3em"})
         .text(group_net_rights[i]['label_text'])
         .title(group_net_rights[i]['label_descr'])
         .data("right", group_net_rights[i]['right'])
         .data("val", is_set?group_net_rights[i]['right']:0)
         .click(function() {
           if(! $(this).hasClass("editable")) return;
           let val=$(this).data("val");
           let right=$(this).data("right");
           $(this).data("val", (val == 0)?right:0).trigger("set");
         })
         .on("set", function() {
           $(this).css(($(this).data("val") == 0)?{"background-color": "lightgray", "color": "gray"}:{"background-color": "lightgreen", "color": "black"});
         })
         .trigger("set")
        ;
        if(gr == undefined) r_label.addClass("editable");

        r_label.appendTo(rigths_span);
      };
    };
  };

  ret.append(rigths_span);
  ret
   .append( $(LABEL)
     .addClass("group")
     .data("id", (gr != undefined)?gr['group_id']:undefined)
     .text((gr != undefined)?gr['group_name']:"Группа не выбрана")
     .css({"margin-left": "1em"})
   )
  ;

  if(opt != undefined && opt['allow_edit'] == true) {
    ret
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-bars").addClass("ui-button").addClass("unedit_btn")
       .css({"color": color_table_buttons})
       .css({"margin-left": "0.3em", "margin-right": "0.3em"})
       .title("Выбрать группу")
       .toggle(gr == undefined)
       .click(function() {
         let row=$(this).closest(".group_rights_div");
         let set_group=row.find(".group").data("id");
         let exclude_list=Array();
         row.parent().find(".group_rights_div").find(".group").each(function() {
           let gr_id=$(this).data("id");
           if(gr_id != undefined && gr_id != set_group && String(gr_id).match(/^\d+$/)) exclude_list.push(gr_id);
         });
         groups_list(set_group, exclude_list, {"allow_add": true, "allow_edit": true, "return": "one", 'allow_user_info_btn': false}, function(group) {
           row.find(".group").data("id", group['group_id']).text(group['group_name']).trigger("set");
         });
       })
     )
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-gears").addClass("ui-button").addClass("edit_btn")
       .css({"color": color_table_buttons})
       .css({"margin-left": "0.3em"})
       .title("Изменить")
       .toggle(gr != undefined)
       .click(function() {
         let row=$(this).closest(".group_rights_div");
         row.find(".right").each(function() {
           $(this).data("val_save", $(this).data("val")).addClass("editable").show();
         });
         row.css({"background-color": "yellow"});
         row.find(".unedit_btn").show();
         row.find(".edit_btn").hide();
         
       })
     )
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-arrowrefresh-1-s").addClass("ui-button").addClass("unedit_btn")
       .css({"color": color_table_buttons})
       .css({"margin-left": "0.3em"})
       .title("Отмена")
       .toggle(gr == undefined)
       .click(function() {
         let row=$(this).closest(".group_rights_div");
         row.find(".right").each(function() {
           let saved_val=$(this).data("val_save");
           $(this).data("val", saved_val).removeClass("editable").trigger("set").toggle(saved_val != 0);
         });
         row.css({"background-color": "initial"});
         row.find(".edit_btn").show();
         row.find(".unedit_btn").hide();
       })
     )
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-disk").addClass("ui-button").addClass("unedit_btn")
       .css({"color": color_table_buttons})
       .css({"margin-left": "0.3em"})
       .title("Установить. Внимание, изменения будут применены при сохранении в родительском окне!")
       .toggle(gr == undefined)
       .click(function() {
         let row=$(this).closest(".group_rights_div");
         let gr_id=row.find(".group").data("id");
         if(gr_id == undefined || !String(gr_id).match(/^\d+$/)) {
           row.find(".group").animateHighlight();
           return;
         };
         row.find(".right").each(function() {
           let val=$(this).data("val");
           $(this).removeClass("editable").toggle(val != 0);
         });
         row.css({"background-color": "initial"});
         row.find(".edit_btn").show();
         row.find(".unedit_btn").hide();
       })
     )
    ;
  };
  if(opt != undefined && opt['allow_edit'] == true) {
    ret
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-trash").addClass("ui-button").addClass("unedit_btn")
       .css({"color": color_table_buttons})
       .css({"margin-left": "0.7em"})
       .title("Удалить группу из списка")
       .toggle(gr == undefined)
       .click(function() {
         let row=$(this).closest(".group_rights_div");
         let f=function() { row.remove(); };
         if(row.find(".group").data("id") == undefined) {
           f();
         } else {
           show_confirm("Подтвердите удаление группы из списка", f);
         };
       })
     )
    ;
  };
  return ret;
};

function v4_global_range_dialog(v4r_id, donefunc) {
  if(v4r_id == undefined && donefunc == undefined) { error_at(); return; };
  if( $("#v4_global_range_dialog").length != 0) return;

  let title;

  if(v4r_id == undefined) {
    title = "Добавление глобального диапазона";
  } else {
    if(donefunc == undefined) {
      title = "Просмотр глобального диапазона";
    } else {
      title = "Редактирование глобального диапазона";
    };
  };

  let dialog=$(DIV).id("v4_global_range_dialog")
   .data("id", v4r_id)
   .addClass("dialog_start")
   .prop("title", title)
   .css({"white-space": "pre", "font-size": "larger"})
   .appendTo("BODY")
  ;

  let d={
    modal:false,
    maxHeight:1000,
    maxWidth:1000,
    minWidth:600,
    width: "auto",
    buttons: [],
    close: function() {
      $(".range_btn").hide();
      $(this).dialog("destroy");
      $(this).remove();
    }
  };

  if(has_right(R_SUPER)) {
    d['buttons'].push({
      "text": (v4r_id == undefined?"Создать":"Сохранить"),
      "click": function() {
        let _this=this;
        let groups=Array();
        let highlight=undefined;
        let hl_count=0;
        let groups_rights={};
        $(this).find(".group_rights_div").each(function() {
          let gr_id=$(this).find(".group").data("id");
          if(gr_id == undefined) {
            if(highlight == undefined) {
              highlight = $(this).find(".group");
            } else {
              highlight.add( $(this).find(".group") );
            };
          } else {
            if(in_array(groups, gr_id)) { error_at(); throw("Error"); };
            groups.push(gr_id);

            let rmask=0;
            $(this).find(".right").each(function() {
              let val=$(this).data("val");
              rmask = (rmask | Number(val)) >>> 0;
            });

            groups_rights[gr_id]=rmask;
          };
        });
        if(highlight != undefined) {
          highlight.animateHighlight();
          return;
        };

        if(!validate_v4range()) return;

        let range_start=$("INPUT#v4range_start").val();
        let range_stop=$("INPUT#v4range_stop").val();

        let range_name=$("INPUT#v4range_name").val();
        let range_descr=$("TEXTAREA#v4range_descr").val();

        let range_style=$("INPUT#v4range_style").val();
        if(!validate_json(range_style)) {
          $("INPUT#v4range_style").animateHighlight();
          return;
        };

        let range_icon=$("INPUT#v4range_icon").val();
        let range_icon_style=$("INPUT#v4range_icon_style").val();
        if(!validate_json(range_icon_style)) {
          $("INPUT#v4range_icon_style").animateHighlight();
          return;
        };

        let query={"range_start": v4ip2long(range_start), "range_stop": v4ip2long(range_stop),
                   "range_name": range_name, "range_descr": range_descr,
                   "range_visible": $("INPUT#v4range_invisible").is(":checked")?0:1,
                   "range_style": range_style, "range_icon": range_icon, "range_icon_style": range_icon_style,
                   "groups_rights": groups_rights
        };

        if(v4r_id == undefined) {
          query['action'] = "v4_add_global_range";
        } else {
          query['action'] = "v4_edit_global_range";
          query['range_id'] = v4r_id;
        };

        run_query(query, function(data) {
          $(_this).dialog("close");
          if(donefunc != undefined) donefunc(data);
        });
      }
    });
  };

  d['buttons'].push({ "text": (donefunc != undefined && has_right(R_SUPER))?"Отмена":"Закрыть", "click": function() {$(this).dialog( "close" ); } });

  let table=$(TABLE);

  table
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Начало:") )
     )
     .append( $(TD)
       .append( $(INPUT).id("v4range_start").prop({"placeholder": "x.x.x.x", "readonly": !has_right(R_SUPER)})
         .on("change input", validate_v4range)
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Окончание:") )
     )
     .append( $(TD)
       .append( $(INPUT).id("v4range_stop").prop({"placeholder": "x.x.x.x", "readonly": !has_right(R_SUPER)})
         .on("change input", validate_v4range)
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Наименование:") )
     )
     .append( $(TD)
       .append( $(INPUT).id("v4range_name").prop({"placeholder": "Краткое наименование", "readonly": !has_right(R_SUPER)})
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Описание:") )
     )
     .append( $(TD)
       .append( $(TEXTAREA).id("v4range_descr").prop({"readonly": !has_right(R_SUPER)})
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Скрытый:") )
     )
     .append( $(TD)
       .append( $(INPUT).id("v4range_invisible").prop({"type": "checkbox"})
         .click(function() { return has_right(R_SUPER); })
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Стиль линии/текста (JSON):") )
     )
     .append( $(TD)
       .append( $(INPUT).id("v4range_style").prop({"placeholder": "{\"color\": \"red\"}", "readonly": !has_right(R_SUPER)})
         .on("change input", function() { validate_json_elm.call(this, "lightgreen", "red"); })
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Значёк:")
         .dotted("ui-icon-xxx - Класс jQuery UI icon\n&#NNNN; - HTML Unicode символ\nURL - Ссылка на .png, .jpg, .jpeg, .ico, .gif")
       )
     )
     .append( $(TD)
       .append( $(INPUT).id("v4range_icon").prop({"placeholder": "ui-icon-info", "readonly": !has_right(R_SUPER)})
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Стиль значка (JSON):") )
     )
     .append( $(TD)
       .append( $(INPUT).id("v4range_icon_style").prop({"placeholder": "{\"color\": \"red\"}", "readonly": !has_right(R_SUPER)})
         .on("change input", function() { validate_json_elm.call(this, "lightgreen", "red"); })
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Права доступа:") )
     )
     .append( $(TD)
       .append( $(DIV).id("v4range_rights") 
       )
       .append( $(DIV)
         .append( !has_right(R_SUPER)?$(LABEL):$(LABEL).addClass("ui-icon").addClass("ui-icon-plusthick").addClass("ui-button")
           .css({"color": color_table_buttons})
           .title("Добавить группу")
           .click(function() {
             let allow_add=true;
             $("DIV#v4range_rights").find(".group_rights_div").find(".group")
              .each(function() { if($(this).data("id") == undefined) { allow_add=false; return false; }; })
             ;
             if(allow_add) {
               $("DIV#v4range_rights").append( group_net_right_div( undefined, (NR_VIEWNAME | NR_VIEWOTHER | RR_TAKE_NET) >>> 0, {"allow_edit": true, "allow_delete": true}) );
             };
           })
         )
       )
     )
   )
  ;

  table.appendTo( dialog );

  dialog.dialog(d);

  if(v4r_id != undefined) {
    let query={"action": "v4_get_range", "range_id": v4r_id};
    run_query(query, function(data) {
      $("INPUT#v4range_start").val(v4long2ip(data['ok']['range_info']['v4r_start']));
      $("INPUT#v4range_stop").val(v4long2ip(data['ok']['range_info']['v4r_stop']));

      if(data['ok']['range_info']['v4r_name'] == "hidden") {
        $("INPUT#v4range_name").val("Скрыто").css({"color": "gray"});
      } else {
        $("INPUT#v4range_name").val(data['ok']['range_info']['v4r_name']);
      };

      if(data['ok']['range_info']['v4r_descr'] == "hidden") {
        $("TEXTAREA#v4range_descr").val("Скрыто").css({"color": "gray"});
      } else {
        $("TEXTAREA#v4range_descr").val(data['ok']['range_info']['v4r_descr']);
      };

      $("INPUT#v4range_invisible").prop("checked", Number(data['ok']['range_info']['v4r_visible']) == 0);

      $("INPUT#v4range_style").val(data['ok']['range_info']['v4r_style']);
      $("INPUT#v4range_icon").val(data['ok']['range_info']['v4r_icon']);
      $("INPUT#v4range_icon_style").val(data['ok']['range_info']['v4r_icon_style']);

      for(let i=0; i < data['ok']['range_group_rights'].length; i++) {
        $("DIV#v4range_rights").append( group_net_right_div(data['ok']['range_group_rights'][i], (NR_VIEWNAME | NR_VIEWOTHER | RR_TAKE_NET) >>> 0, { "allow_edit": has_right(R_SUPER), "allow_delete": has_right(R_SUPER)}) );
      };
    });
  } else {
  };

};

function v4ranges_calc_show(ranges, ranges_list) {
  clear_calc();

  let calc_cont=$("#calc_text");
  ranges_list.sort(function(a,b) {
    if(ranges[a]['v4r_start'] != ranges[b]['v4r_start']) {
      return Number(ranges[a]['v4r_start']) - Number(ranges[a]['v4r_start']);
    } else if(ranges[a]['v4r_stop'] != ranges[b]['v4r_stop']) {
      return Number(ranges[a]['v4r_stop']) - Number(ranges[a]['v4r_stop']);
    } else {
      return String(ranges[a]['v4r_name']).localeCompare(String(ranges[b]['v4r_name']));
    };
  });

  let table_div=$(DIV).css({"display": "table"});

  for(let i=0; i < ranges_list.length; i++) {
    let r=ranges_list[i];

    let attributes=$(SPAN);

    if(Number(ranges[r]['v4r_visible']) > 0) {
      attributes
       .append( $(LABEL).text(" ")
        // .addClass("ui-icon")
        // .addClass("ui-icon-blank")
         .css(s_ranges_spacing)
       )
      ;
    } else {
      attributes
       .append( $("<S/>")
         .css(s_ranges_spacing)
         .append( $(LABEL).html("&#128065;")
           .css({"color": "gray"})
           .title("Скрытая")
         )
       )
      ;
    };

    if((Number(ranges[r]['rmask']) & RR_TAKE_NET) > 0) {
      attributes
       .append( $(LABEL).addClass("ui-icon")
         .addClass("ui-icon-unlocked")
         .css(s_ranges_spacing)
         .title("Разрешено занимать сети")
       )
      ;
    };

    if((Number(ranges[r]['rmask']) & RR_DENY_TAKE_IP) > 0) {
      attributes
       .append( $(LABEL).addClass("ui-icon")
         .addClass("ui-icon-locked")
         .css(s_ranges_spacing)
         .title("Запрещено занимать/редактировать IP обычным пользователям")
       )
      ;
    };

    let icon;

    if(String(ranges[r]['v4r_icon']).match(/^ui-icon(?:-[a-z0-9]+)+$/)) {
      icon=$(LABEL).addClass("ui-icon")
       .addClass( ranges[r]['v4r_icon'] )
       .css( JSON.parse(ranges[r]['v4r_icon_style']) )
       .css(s_ranges_spacing)
       .title( ranges[r]['v4r_descr'] )
      ;
    } else if(String(ranges[r]['v4r_icon']).match(/^&#[xX]?[0-9a-fA-F]+;$/)) {
      icon=$(LABEL).html( ranges[r]['v4r_icon'] )
       .css( JSON.parse(ranges[r]['v4r_icon_style']) )
       .css(s_ranges_spacing)
       .title( ranges[r]['v4r_descr'] )
      ;
    } else if(String(ranges[r]['v4r_icon']).match(/\.(?:png|jpg|jpeg|ico|gif)$/)) {
      icon=$(IMG).prop("src", ranges[r]['v4r_icon'] )
       .css( JSON.parse(ranges[r]['v4r_icon_style']) )
       .css(s_ranges_spacing)
       .title( ranges[r]['v4r_descr'] )
      ;
    } else {
      icon=$(LABEL).addClass("ui-icon")
       .addClass("ui-icon-arrow-2-n-s")
       .css( JSON.parse(ranges[r]['v4r_icon_style']) )
       .css(s_ranges_spacing)
       .title( ranges[r]['v4r_descr'] )
      ;
    };

    let row=$(DIV).css({"display": "table-row"})
     .addClass("row")
     .data("data", ranges[r])
     .append( $(DIV).css({"display": "table-cell"})
       .append( icon )
     )
     .append( $(DIV).css({"display": "table-cell"})
       .append( attributes )
     )
     .append( $(DIV).css({"display": "table-cell"})
       .append( $(SPAN).text(v4long2ip(ranges[r]['v4r_start'])+" - "+v4long2ip(ranges[r]['v4r_stop']))
         .css({"white-space": "pre", "margin-left": "0.5em"})
         .css( JSON.parse(ranges[r]['v4r_style']) )
         .title( ranges[r]['v4r_descr'] )
       )
     )
     .append( $(DIV).css({"display": "table-cell"})
       .append( $(SPAN).text(ranges[r]['v4r_name'])
         .css({"white-space": "pre", "margin-left": "0.5em"})
         .title( ranges[r]['v4r_descr'] )
       )
     )
     /*.append( $(DIV).css({"display": "table-cell"})
       .append( $(SPAN).text(ranges[r]['_debug'])
         .css({"white-space": "pre", "margin-left": "0.5em"})
         .title( ranges[r]['v4r_descr'] )
       )
     )*/
    ;

    let can_edit=has_right(R_SUPER);

    row
     .append( $(DIV).css({"display": "table-cell"})
       .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-bullets").addClass("ui-button")
         .css({"white-space": "pre", "margin-left": "0.5em"})
         .title(can_edit?"Изменить":"Просмотр")
         .click(function() {
           let _d=$(this).closest(".row").data("data");
           if(_d == "") { error_at(); return; };
           let _id=_d['v4r_id'];
           if(_id == undefined) { error_at(); return; };

           $(".range_btn").show();
           v4_global_range_dialog(_id, can_edit?(function() { process_R(); }):undefined);
         })
       )
     )
    ;

    if(can_edit) {
      row
       .append( $(DIV).css({"display": "table-cell"})
         .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-trash").addClass("ui-button")
           .css({"white-space": "pre", "margin-left": "0.5em"})
           .title("Удалить")
           .click(function() {
             let _d=$(this).closest(".row").data("data");
             if(_d == "") { error_at(); return; };
             let _id=_d['v4r_id'];
             if(_id == undefined) { error_at(); return; };

             show_confirm("Подтвердите удаление диапазона "+v4long2ip(_d['v4r_start'])+" - "+v4long2ip(_d['v4r_stop'])+"\n"+_d['v4r_name'], function() {
               let query={"action": "v4_delete_global_range", "range_id": _id};
               run_query(query, function() { process_R(); });
             });
           })
         )
       )
      ;
    };
    row.appendTo( table_div );
  };
  table_div.appendTo( calc_cont );
  $("#calc").show();
};

function v4calc_show(net, masklen, elm) {
  clear_calc();

  let parent_net=(net & v4len2mask[masklen]) >>> 0;

  let calc_text = "";

  if(parent_net != net) {
    calc_text += "IP: "+v4long2ip(net);
    calc_text += "\nParent net: "+v4long2ip(parent_net)+"/"+masklen;
  } else {
    calc_text += "Network: "+v4long2ip(net)+"/"+masklen;
  };
  calc_text += "\nMask: "+v4long2ip(v4len2mask[masklen]);
  calc_text += "\nWildcard: "+ v4long2ip( (~v4len2mask[masklen]) >>> 0);
  if(parent_net != net) {
    calc_text += "\nParent Last IP: "+v4long2ip((parent_net | ~v4len2mask[masklen]) >>> 0);
  } else {
    calc_text += "\nLast IP: "+v4long2ip((net | ~v4len2mask[masklen]) >>> 0);
  };

  $("#calc_text").text(calc_text);
  $("#calc").show();

  $("#calc_text").animateHighlight("lightgreen");

  if(elm != undefined) {
    let elm_bg_color=elm.css("background-color");
    if(elm_bg_color != "lightgreen") {
      elm.data("saved_bg_color", elm_bg_color);
    };
    elm.css({"background-color": "lightgreen"}).addClass("calc_highlight");
  };
};

function v4nav(data) {
  let func_start=Date.now();

  let contents=$("#contents");
  if(contents.length != 1) {
    error_at();
    return;
  };

  contents.empty();

  let page_title="Навигация: "+data['net_info']['net_text']+"/"+data['net_info']['masklen'];

  document.title="IPDB: "+page_title;
  saveQuery(page_title);
  $("#page_title").text(page_title);

  let show_range_select= $("#v4_global_range_dialog").length == 1 && has_right(R_SUPER);

  let table=$(TABLE)
   .css({"border-collapse": "collapse", "font-size": "large"})
   .data("ext_ranges", data['ext_ranges'])
   .appendTo(contents)
  ;

  let thead=$(THEAD)
   .appendTo(table)
  ;
  let htr=$(TR)
   .css({"position": "relative", "background-color": "white"})
   .appendTo(thead)
  ;

  let masklen_start = Number(data['net_info']['masklen']) + 1;
  let masklen_stop;

  let first_ip_octets=ip4octets(data['net_info']['net']);
  let last_ip_octets=ip4octets(data['net_info']['net_last']);

  let octet_index;

  if(Number(data['net_info']['masklen']) < 8) {
    masklen_stop = 8;
    octet_index = 0;
  } else if(Number(data['net_info']['masklen']) < 16) {
    masklen_stop = 16;
    octet_index = 1;
  } else if(Number(data['net_info']['masklen']) < 24) {
    masklen_stop = 24;
    octet_index = 2;
  } else {
    masklen_stop = 32;
    octet_index = 3;
  };

  let top_masklen;

  if(Number(data['net_info']['masklen']) <= 8) {
    top_masklen = 0;
  } else if(Number(data['net_info']['masklen']) <= 16) {
    top_masklen = 8;
  } else if(Number(data['net_info']['masklen']) <= 24) {
    top_masklen = 16;
  } else {
    top_masklen = 24;
  };

  let first_octet=first_ip_octets[octet_index];
  let last_octet=last_ip_octets[octet_index];

  let top_left=$(TH).text("") //top-left corner
   .css({"position": "sticky", "top": "0", "background-color": "white", "z-index": 1, "border-bottom": "1px solid gray", "padding-left": "0.2em"})
   .appendTo(htr)
  ;

  if(Number(data['net_info']['masklen']) != 0) {
    let top_net = (Number(data['net_info']['net']) & v4len2mask[top_masklen]) >>> 0;
    top_left
     .append( $(SPAN).addClass("ui-icon").addClass("ui-icon-caret-2-n")
       .addClass("ui-button")
       .css({"margin-left": "0.2em", "margin-right": "0.2em"})
       .css({"padding-left": "0.2em", "padding-right": "0.2em", "color": color_table_buttons})
       .title("Перейти на уровень выше. К сети "+v4long2ip(top_net)+"/"+top_masklen)
       .data({"net": top_net, "masklen": top_masklen})
       .click(function() {
         let _net=$(this).data("net");
         let _masklen=$(this).data("masklen");
         let hide_empty= $R['hide_empty'] == undefined ? "0":$R['hide_empty'];
         $R={"action": "v4get_net", "net": _net, "masklen": _masklen, "hide_empty": hide_empty};
         v4get_net();
       })
     )
    ;

  } else {
    top_left
     .append( $(SPAN).addClass("ui-icon").addClass("ui-icon-blank")
       .css({"margin-left": "0.2em", "margin-right": "0.2em"})
       .css({"padding-left": "0.2em", "padding-right": "0.2em"})
     )
    ;
  };

  top_left
   .append( $(SPAN).addClass("ui-icon").addClass("ui-icon-refresh")
     .addClass("ui-button")
     .css({"margin-left": "0.2em", "margin-right": "0.2em"})
     .css({"padding-left": "0.2em", "padding-right": "0.2em", "color": color_table_buttons})
     .title("Обновить данные")
     .data({"net": data['net_info']['net'], "masklen": data['net_info']['masklen']})
     .click(function() {
       let _net=$(this).data("net");
       let _masklen=$(this).data("masklen");
       let hide_empty= $R['hide_empty'] == undefined ? "0":$R['hide_empty'];
       $R={"action": "v4get_net", "net": _net, "masklen": _masklen, "hide_empty": hide_empty };
       v4get_net();
     })
   )
  ;

  top_left
   .append( $(SPAN).addClass("ui-icon").addClass("ui-icon-info")
     .addClass("ui-button")
     .css({"margin-left": "0.2em", "margin-right": "0.2em"})
     .css({"padding-left": "0.2em", "padding-right": "0.2em", "color": color_table_buttons})
     .title("Показать маску сети и прочие расчетные данные. Также клик на любой ячейке выведет данные по соответствующей подсети/маске.")
     .data({"net": data['net_info']['net'], "masklen": data['net_info']['masklen']})
     .click(function() {
       let _net=$(this).data("net");
       let _masklen=$(this).data("masklen");
       v4calc_show(_net, _masklen, $(this).closest("TH"));
     })
   )
  ;

  let eye_color;
  let eye_title;

  if($R['hide_empty'] != "1") {
    eye_color=color_table_buttons;
    eye_title="Скрыть пустые строки";
  } else {
    eye_color="orange";
    eye_title="Показать пустые строки";
  };

  top_left
   .append( $(SPAN).addClass("ui-icon").addClass("ui-icon-eye")
     .addClass("ui-button")
     .css({"margin-left": "0.2em", "margin-right": "0.2em"})
     .css({"padding-left": "0.2em", "padding-right": "0.2em", "color": eye_color})
     .title(eye_title)
     .data({"net": data['net_info']['net'], "masklen": data['net_info']['masklen']})
     .click(function() {
       let _net=$(this).data("net");
       let _masklen=$(this).data("masklen");
       let hide_empty= $R['hide_empty'] == "1" ? "0":"1";
       $R={"action": "v4get_net", "net": _net, "masklen": _masklen, "hide_empty": hide_empty };
       v4get_net();
     })
   )
  ;

  for(let cur_masklen=masklen_start; cur_masklen <= masklen_stop; cur_masklen++) {
    $(TH).text("/"+cur_masklen)
     .css({"position": "sticky", "top": "0", "background-color": "white", "z-index": 1, "border-bottom": "1px solid gray", "border-left": "1px solid gray"})
     .appendTo(htr)
    ;
  };

  //net name column
  $(TH)
   .css({"position": "sticky", "top": "0", "background-color": "white", "z-index": 1, "border-bottom": "1px solid gray", "border-left": "1px solid gray"})
   .appendTo(htr)
  ;

  //ranges column
  let r_th=$(TH)
   .css({"position": "sticky", "top": "0", "background-color": "white", "z-index": 1, "border-bottom": "1px solid gray", "border-left": "1px solid gray"})
   .appendTo(htr)
  ;

  let tbody=$(TBODY)
   .appendTo(table)
  ;

  let rows_octets=first_ip_octets.slice();

  let last_net=undefined;

  let outer_ranges=Array();
  let inner_ranges=Array();
  let inside_ranges=Array();

  let cut_net_mask=v4len2mask[ masklen_stop ];
  let cut_net_wildcard= (~cut_net_mask) >>> 0;

  for(r in data['ext_ranges']) {
    if(Number(data['ext_ranges'][r]['v4r_visible']) > 0 || has_right(R_SUPER)) {
      if(Number(data['net_info']['net']) > Number(data['ext_ranges'][r]['v4r_start']) &&
         Number(data['net_info']['net_last']) < Number(data['ext_ranges'][r]['v4r_stop'])
      ) {
        outer_ranges.push(r);
        data['ext_ranges'][r]['_hit'] = true;
        data['ext_ranges'][r]['_debug'] = "outer";
      } else {
        let r_start_net = (Number(data['ext_ranges'][r]['v4r_start']) & cut_net_mask) >>> 0;
        let r_stop_net = (Number(data['ext_ranges'][r]['v4r_stop']) & cut_net_mask) >>> 0;

        let r_start_host = (Number(data['ext_ranges'][r]['v4r_start']) & cut_net_wildcard) >>> 0;
        let r_stop_host = (Number(data['ext_ranges'][r]['v4r_stop']) & cut_net_wildcard) >>> 0;
        let r_stop_host_next = ((Number(data['ext_ranges'][r]['v4r_stop'])+1) & cut_net_wildcard) >>> 0;

        if(r_start_net == r_stop_net && (r_start_host > 0 && r_stop_host_next > 0)) {
          inside_ranges.push(r);
          data['ext_ranges'][r]['_debug'] = "inside";
        } else {
          inner_ranges.push(r);
          data['ext_ranges'][r]['_debug'] = "inner";
        };
      };
    };
  };

  inner_ranges.sort(function(a,b) {
    if(data['ext_ranges'][a]['v4r_start'] != data['ext_ranges'][b]['v4r_start']) {
      return Number(data['ext_ranges'][a]['v4r_start']) - Number(data['ext_ranges'][a]['v4r_start']);
    } else if(data['ext_ranges'][a]['v4r_stop'] != data['ext_ranges'][b]['v4r_stop']) {
      return Number(data['ext_ranges'][a]['v4r_stop']) - Number(data['ext_ranges'][a]['v4r_stop']);
    } else {
      return String(data['ext_ranges'][a]['v4r_name']).localeCompare(String(data['ext_ranges'][b]['v4r_name']));
    };
  });


  let outer_ranges_span=undefined;

  if(outer_ranges.length > 0) {
    outer_ranges_span=$(LABEL).html("&#x26AB;")
     //.addClass("ui-icon").addClass("ui-icon-bullet")
     .css({"color": "green"})
     .css(s_ranges_spacing)
     .data("ranges", outer_ranges)
     .title(outer_ranges.length+" "+ranges2lang(false, "ru", outer_ranges.length)+", в которые сеть входит целиком. Нажмите на этот значёк для подробной информации.")
     .click(function() {
       let _ranges_list=$(this).data("ranges");
       let _ranges=$(this).closest("TABLE").data("ext_ranges");
       v4ranges_calc_show(_ranges, _ranges_list);
     })
     .appendTo( r_th )
    ;
  };

  if(has_right(R_SUPER)) {
    r_th
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-plusthick").addClass("ui-button")
       .css(s_ranges_spacing)
       .css({"color": color_table_buttons})
       .title("Добавить диапазон")
       .click(function() {
         $(".range_btn").show();
         v4_global_range_dialog(undefined, function() { process_R(); });
       })
     )
    ;
  };

  let bg_count=0;
  let hidden_count=0;

  for(let o=first_octet; o <= last_octet; o++) {
    rows_octets[octet_index] = o;

    let row_ip_text=rows_octets[0]+"."+rows_octets[1]+"."+rows_octets[2]+"."+rows_octets[3];

    let row_net=v4oct2long(rows_octets[0], rows_octets[1], rows_octets[2], rows_octets[3]);
    let row_last=(row_net | ~v4len2mask[masklen_stop]) >>> 0;

    if(last_net != undefined &&
       row_net > last_net['v4net_last']
    ) {
      last_net = undefined;
    };

    let row_hideable=true;
    let row_has_nets=false;

    for(n in data['nets']) {
      if(row_net >= data['nets'][n]['v4net_addr'] && row_net <= data['nets'][n]['v4net_last']) {
        row_hideable=false;
        row_has_nets=true;
        break;
      };
    };

    if(data['aggr_nets'][ row_net ] != undefined) {
      row_hideable=false;
      row_has_nets=true;
    };

    let tr=$(TR);

    tr
     .append( $(TD).text(row_ip_text)
       .css({"border-bottom": "1px solid gray", "padding-left": "0.5em", "padding-right": "0.5em"})
       .title( v4long2ip(row_last) )
     )
    ;
    for(let cur_masklen=masklen_start; cur_masklen <= masklen_stop; cur_masklen++) {
      let cell_style={};

      let mask_net = (row_net & v4len2mask[cur_masklen]) >>> 0;
      let mask_net_last = (mask_net | (~v4len2mask[cur_masklen] >>> 0)) >>> 0;


      let taken=false;

      let view = false;
      if(data['nets'][ row_net ] != undefined &&
         data['nets'][ row_net ]['v4net_mask'] == cur_masklen
      ) {
        taken = true;
        last_net = data['nets'][ mask_net ];
        last_net_octets=ip4octets(mask_net);
        last_net['net_text']=last_net_octets[0]+"."+last_net_octets[1]+"."+last_net_octets[2]+"."+last_net_octets[3];
        view=true;
      };

      if(!taken && last_net != undefined &&
         row_net >= last_net['v4net_addr'] &&
         row_net <= last_net['v4net_last'] &&
         cur_masklen >= last_net['v4net_mask']
      ) {
        taken = true;
      };



      //let takable= (row_net == mask_net) && !taken && data['aggr_nets'][ row_net ] == undefined;
      let takable= (row_net == mask_net) && !taken;

      if(takable && data['aggr_nets'][ row_net ] != undefined) {
        takable = false;
        cell_style['background-color']=color_taken;
      };

      if(takable) {
        for(n in data['nets']) {
          if(data['nets'][n]['v4net_addr'] >= mask_net && data['nets'][n]['v4net_addr'] <= mask_net_last) {
            takable = false;
            cell_style['background-color']=color_taken;
            break;
          };
        };
      };

      if(takable) {
        for(n in data['aggr_nets']) {
          if(data['aggr_nets'][n]['aggr_net'] >= mask_net && data['aggr_nets'][n]['aggr_net'] <= mask_net_last) {
            takable = false;
            cell_style['background-color']=color_taken;
            break;
          };
        };
      };

      if(takable && !has_right(R_SUPER)) {
        let rmask=0;
        for(r in outer_ranges) {
          if(mask_net >= data['ext_ranges'][r]['v4r_start'] && mask_net_last <= data['ext_ranges'][r]['v4r_stop']) {
            rmask = rmask | Number(data['ext_ranges'][r]['rmask']);
            if( (rmask & RR_TAKE_NET) > 0) break;
          };
        };
        if( (rmask & RR_TAKE_NET) == 0) {
          for(r in inner_ranges) {
            if(mask_net >= data['ext_ranges'][r]['v4r_start'] && mask_net_last <= data['ext_ranges'][r]['v4r_stop']) {
              rmask = rmask | Number(data['ext_ranges'][r]['rmask']);
              if( (rmask & RR_TAKE_NET) > 0) break;
            };
          };
        };

        if( (rmask & RR_TAKE_NET) == 0) {
          takable = false;
        };
      };

      let navigatable = (row_net == mask_net) && !taken && (cur_masklen < 32);

      if(taken) {
        cell_style['background-color']=color_taken;
      };

      let td=$(TD)
       .css({"border-bottom": "1px solid gray", "border-left": "1px solid gray", "min-width": "4.5em", "position": "relative"})
       .data({"net": row_net, "masklen": cur_masklen})
       .click(function(e) {
         if(e.target != this && !$(e.target).hasClass("ui-icon-blank")) return;
         let _net = $(this).data("net");
         let _masklen = $(this).data("masklen");

         v4calc_show(_net, _masklen, $(this));
       })
      ;

      if(has_right(R_SUPER)) {
        if(cur_masklen == masklen_start) {
          let range_start=v4long2ip(row_net);
          td
           .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-caret-1-nw")
             .addClass("ui-button")
             .addClass("range_btn")
             .css({"position": "absolute", "top": 0, "left": 0, "font-size": "49%"})
             .toggle(show_range_select)
             .data("range_start", range_start)
             .title("Установить начало диапазона: "+range_start)
             .click(function() {
               let _addr=$(this).data("range_start");
               $("INPUT#v4range_start").val(_addr).trigger("input");
             })
           )
          ;
        };
        if(cur_masklen == masklen_stop) {
          let range_stop=v4long2ip(row_last);
          td
           .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-caret-1-se")
             .addClass("ui-button")
             .addClass("range_btn")
             .css({"position": "absolute", "bottom": 0, "right": 0, "font-size": "49%"})
             .toggle(show_range_select)
             .data("range_stop", range_stop)
             .title("Установить окончание диапазона: "+range_stop)
             .click(function() {
               let _addr=$(this).data("range_stop");
               $("INPUT#v4range_stop").val(_addr).trigger("input");
             })
           )
          ;
        };
      };

      if(taken) {
        if(view) {
          if(has_right(R_VIEWANY) || (data['nets'][row_net]['rmask'] & NR_VIEWOTHER) > 0) {
            td
             .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-bullets")
               .addClass("ui-button")
               .css({"padding-left": "0.2em", "padding-right": "0.2em", "color": color_table_buttons})
               .css({"position": "absolute", "left": "2.1em", "top": "0.2em"})
               .title("Перейти к просмотру сети "+row_ip_text+"/"+cur_masklen)
               .data({"net": row_net, "masklen": cur_masklen})
               .click(function() {
                 let _net=$(this).data("net");
                 let _masklen=$(this).data("masklen");
                 $R={"action": "v4get_net", "net": _net, "masklen": _masklen};
                 v4get_net();
               })
             )
            ;
          } else {
            td
             .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-locked")
               .addClass("ui-button")
               .css({"padding-left": "0.2em", "padding-right": "0.2em", "color": color_table_buttons})
               .css({"position": "absolute", "left": "2.1em", "top": "0.2em"})
               .title("Доступ к просмотру сети "+row_ip_text+"/"+cur_masklen+" запрещен")
             )
            ;
          };
        } else {
          /*
          td
           .append( $(SPAN).addClass("ui-icon").addClass("ui-icon-blank")
             .css({"padding-left": "0.2em", "padding-right": "0.2em"})
           )
          ;
          */
          td.title("Входит в сеть "+last_net['net_text']+"/"+last_net['v4net_mask']);
        };
        /*
        td
         .append( $(SPAN).addClass("ui-icon").addClass("ui-icon-blank")
           .css({"padding-left": "0.2em", "padding-right": "0.2em"})
         )
        ;
        */
      } else {
        if(takable) {
          td
           .append( $(SPAN).addClass("ui-icon").addClass("ui-icon-cart")
             .addClass("ui-button")
             .css({"padding-left": "0.2em", "padding-right": "0.2em", "color": color_table_buttons})
             //.css({"margin-left": "0.2em", "margin-right": "0.2em"})
             .css({"position": "absolute", "left": "1.1em", "top": "0.2em"})
             .title("Занять сеть "+row_ip_text+"/"+cur_masklen)
             .data({"net": row_net, "masklen": cur_masklen})
             .click(function() {
               let _net=$(this).data("net");
               let _masklen=$(this).data("masklen");
             })
           )
          ;
        } else {
          /*
          td
           .append( $(SPAN).addClass("ui-icon").addClass("ui-icon-blank")
             .css({"padding-left": "0.2em", "padding-right": "0.2em"})
           )
          ;
          */
        };
        if(navigatable) {
          td
           .append( $(SPAN).addClass("ui-icon").addClass("ui-icon-sitemap")
             .addClass("ui-button")
             .css({"padding-left": "0.2em", "padding-right": "0.2em", "color": color_table_buttons})
             //.css({"margin-left": "0.2em", "margin-right": "0.2em"})
             .css({"position": "absolute", "left": "3.1em", "top": "0.2em"})
             .title("Навигация по подсетям "+row_ip_text+"/"+cur_masklen)
             .data({"net": row_net, "masklen": cur_masklen})
             .click(function() {
               let _net=$(this).data("net");
               let _masklen=$(this).data("masklen");
               let hide_empty= $R['hide_empty'] == undefined ? "0":$R['hide_empty'];
               $R={"action": "v4get_net", "net": _net, "masklen": _masklen, "hide_empty": hide_empty };
               v4get_net();
             })
           )
          ;
        } else {
          /*
          td
           .append( $(SPAN).addClass("ui-icon").addClass("ui-icon-blank")
             .css({"padding-left": "0.2em", "padding-right": "0.2em"})
           )
          ;
          */
        };
      };

      td
       .css(cell_style)
       .appendTo(tr)
      ;
    };

    // net name TD
    let net_td=$(TD);

    if(data['nets'][ row_net ] !== undefined) {
      if(data['nets'][ row_net ]['v4net_name'] == 'hidden') {
        net_td.text("Скрыто")
         .title("У вас нет прав на просмотр сети")
         .css({"color": "gray"})
        ;
      } else {
        net_td.text(data['nets'][ row_net ]['v4net_name'])
         .title(data['nets'][ row_net ]['v4net_descr'])
        ;
      };
    } else if(data['aggr_nets'][ row_net ] !== undefined) {
      net_td.text("... " + data['aggr_nets'][ row_net ]['aggr_count'] + " " + nets2lang(false, 'ru', data['aggr_nets'][ row_net ]['aggr_count']));
    };

    let net_name_css={"padding-left": "0.5em", "padding-right": "0.5em", "border-bottom": "1px solid gray", "border-left": "1px solid gray"};
    if(row_has_nets) net_name_css['background-color'] = color_taken;

    tr
     .append( net_td
       .css(net_name_css)
     )
    ;

    //ranges TD

    let r_td=$(TD);
    let r_css={"background-color": "white"};

    for(let i=0; i < inner_ranges.length; i++) {
      let r=inner_ranges[i];
      let range=data['ext_ranges'][r];

      let r_elm=$(LABEL)
       .css(s_ranges_spacing)
      ;

      if(row_net > Number(range['v4r_stop']) || row_last < Number(range['v4r_start'])) {
        r_elm.html(" ");
      } else {
        if(row_net <= Number(range['v4r_start']) || row_last >= Number(range['v4r_stop'])) {
          row_hideable=false;
        };
          
        data['ext_ranges'][r]['_hit'] = true;
        r_elm.range_symbol(row_net, row_last, Number(range['v4r_start']), Number(range['v4r_stop']));

        r_elm
         .title(ranges2lang(true, "ru", 1)+": "+v4long2ip(range['v4r_start'])+" - "+v4long2ip(range['v4r_stop'])+"\n"+range['v4r_name']+"\nНажмите для более подробной информации")
         .css(JSON.parse(range['v4r_style']))
         .data("ranges", [ r ])
         .click(function() {
           let _ranges_list=$(this).data("ranges");
           let _ranges=$(this).closest("TABLE").data("ext_ranges");
           v4ranges_calc_show(_ranges, _ranges_list);
         })
         .dblclick(function(e) {
           e.stopPropagation();
           let _ranges_list=$(this).data("ranges");
           let _ranges=$(this).closest("TABLE").data("ext_ranges");
           let can_edit=has_right(R_SUPER);
           if(can_edit) $(".range_btn").show();
           v4_global_range_dialog(_ranges[_ranges_list[0]]['v4r_id'], can_edit?(function() { process_R(); }):undefined);
         })
        ;
      };

      r_elm.appendTo( r_td )
    };

    if(inside_ranges.length > 0) {
      let r_elm=$(LABEL)
       .css(s_ranges_spacing)
      ;

      let row_inside_ranges=Array();

      for(let i=0; i < inside_ranges.length; i++) {
        let r=inside_ranges[i];
        let range=data['ext_ranges'][r];
        if(row_net < Number(range['v4r_start']) && row_last > Number(range['v4r_stop'])) {
          row_inside_ranges.push(r);
          data['ext_ranges'][r]['_hit'] = true;
        };
      };

      if(row_inside_ranges.length == 0) {
        r_elm.html(" ");
      } else {
        row_hideable=false;

        r_elm.html("&#x25c0;") // ◀, range is inside row net
         .title(row_inside_ranges.length+" "+ranges2lang(false, "ru", outer_ranges.length)+" внутри подсети.\nНажмите для более подробной информации")
         .data("ranges", row_inside_ranges)
         .click(function() {
           let _ranges_list=$(this).data("ranges");
           let _ranges=$(this).closest("TABLE").data("ext_ranges");
           v4ranges_calc_show(_ranges, _ranges_list);
         })
        ;
      };

      r_elm.appendTo(r_td);
    };

    tr
     .append( r_td
       .css(r_css)
     )
    ;

    if(row_hideable) {
      tr.addClass("hideable").toggle( $R['hide_empty'] != "1" );
    };

    if(!row_hideable || $R['hide_empty'] != "1" ) {
      bg_count++;
    } else {
      hidden_count++;
    };

    if(bg_count % 2) {
      tr.css({"background-color": color_odd});
    } else {
      tr.css({"background-color": color_even});
    };

    tr.appendTo(tbody);
  };

  if(hidden_count > 0) {
    $(TR)
     .append( $(TD).prop("colspan", "99").css({"text-align": "center"})
       .append( $(SPAN).text( hidden_count+" пустых строк скрыто") )
     )
     .appendTo(tbody);
    ;
  };


  let not_hit=Array();

  for(let r in data['ext_ranges']) {
    if(!data['ext_ranges'][r]['_hit']) {
      not_hit.push(r);
    };
  };

  if(not_hit.length == 0) {
    v4calc_show(data['net_info']['net'], data['net_info']['masklen'], top_left);
  } else {
    v4ranges_calc_show(data['ext_ranges'], not_hit);
  };


  let func_stop=Date.now();
  //$("#debug").text( func_stop - func_start );
};

function v4view(data) {
  saveQuery("IPv4 view");
  return;
  let contents=$("#contents");
  if(contents.length != 1) {
    error_at();
    return;
  };

  contents.empty();

  $("#page_title").text("IPv4 view");
};

function v4get_net() {
  require_param("action", /^v4get_net$/);
  require_param("net", "v4long");
  require_param("masklen", "v4masklen");

  let contents=$("#contents");
  if(contents.length != 1) {
    error_at();
    return;
  };

  $(DIV)
   .css({"position": "fixed", "top": "49%", "left": "0", "right": "0", "height": "auto", "text-align": "center"})
   .append( $(DIV).text("Загрузка")
     .css({"display": "inline-block", "background-color": "white", "font-size": "400%", "border": "2px solid gray", "padding": "0.5em"})
   )
   .appendTo( contents )
  ;

  run_query({"action": "v4get_net", "net": $R['net'], "mask": $R['masklen']}, function(data) {
    if(data["ok"]["type"] == "nav") {
      v4nav(data["ok"]);
    } else {
      v4view(data["ok"]);
    };
  });
};

function ipv4() {
  require_param("action", /^ipv4$/);
  saveQuery();
  let contents=$("#contents");
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
             let hide_empty= $R['hide_empty'] == undefined ? "0":$R['hide_empty'];
             $R={ "action": "v4get_net", "net": 0, "masklen": 0, "hide_empty": hide_empty };
             v4get_net();
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

function process_R() {
  if($R['action'] == "ipv4") {
    ipv4();
  } else if($R['action'] == "v4get_net") {
    v4get_net();
  } else {
    $R={'action': "ipv4"};
    ipv4();
  };
};

$( document ).ready(function() {

  window.onpopstate=function(e) {
    $R=e.state;
    process_R();
  };

  page_root=window.location.href.split("?")[0];
  let qs=window.location.search.substring(1);

  qs.split("&").forEach(function(vp) {
    vpa=vp.split("=");
    let key=undefined;
    let val=undefined;

    if(vpa.length == 1) {
      key=vpa[0];
      val=true;
    } else {
      key=vpa[0];
      val=decodeURIComponent(vpa[1]);
    };

    if(key.substring(key.length-2, key.length) == "[]") {
      key=key.substring(0, key.length-2);
      if(key.length > 0) {
        if($R[ key ] === undefined) {
          $R[ key ] = Array();
        };
        $R[ key ].push(val);
      };
    } else {
      $R[ key ] = val;
    };
  });

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
   .append( $(DIV).id("calc")
     .css({
       "position": "fixed", "bottom": "2em", "right": "2em", "width": "auto", "height": "auto",
       "z-index": 1000000
     })
     .append( $(DIV)
       .css({"border": "1px solid black", "display": "inline-block"})
       .css({"padding": "0.2em"})
       .append( $(SPAN).addClass("ui-icon").addClass("ui-icon-close")
         .click(function() {
           $(".calc_highlight").each(function() { $(this).removeClass("calc_highlight").css({"background-color": "initial"}); });
           $("#calc").hide();
         })
       )
     )
     .append( $(DIV).id("calc_text")
       .css({"padding": "0.2em"})
       .css({"border": "1px solid black"})
       .css({"white-space": "pre"})
     )
     .hide()
   )
  ;

  if($R['action'] == undefined) {
    $R['action']='ipv4';
  };

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

           window.location.href="logout.php?back_uri="+encodeURIComponent(page_root);
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

      
      $("#user_info")
       .append( $(SPAN).addClass("ui-icon").addClass("ui-icon-contact")
         .title("debug info")
         .css({"margin-right": "0.5em"})
         .css(s_blocks_color)
         .click(function() {
           user_edit(ud['user']['user_id'], {'allow_groups_change': true});
           clear_calc();
           let calc_cont=$("#calc_text");
           calc_cont
            .append( $(DIV).css({"white-space": "pre"})
              .text( JSON.stringify(ud, null, "  ") )
            )
           ;
           $("#calc").show();
         })
       )
      ;

      $("#user_info").append( $(SPAN).text(data["ok"]["user"]["user_name"]) );


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
        $(DIV).id("contents")
         .css({"margin-top": "3em"})
         .appendTo("BODY")
        ;
        menu_bar
         .append( $(SPAN).addClass("ui-button").text("IPv4")
           .css({"padding": "0px 0.3em", "margin-left": "10px"})
           .click(function() {
             $R={"action": "ipv4"};
             ipv4();
           })
         )
        ;

        menu_bar
         .append( $(SPAN).addClass("ui-button").text("Группы")
           .css({"padding": "0px 0.3em", "margin-left": "10px"})
           .click(function() {
             groups_list([], [], { "allow_add": has_right(R_SUPER), "allow_edit": has_right(R_SUPER), "allow_user_info_btn": false });
           })
         )
        ;

        menu_bar
         .append( $(SPAN).addClass("ui-button").text("Пользователи")
           .css({"padding": "0px 0.3em", "margin-left": "10px"})
           .click(function() {
             users_list([], { "allow_user_info_btn": true, "allow_user_group_change": has_right(R_SUPER) });
           })
         )
        ;

        process_R();
      };
    };
  });
});
