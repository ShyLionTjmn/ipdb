// GLOBALS
var ud;
var $R={};
var page_root;

var g_checks={};

var _debug_opts=true;

var VLANS_AUTOSAVE=true;
var TEMPLATES_AUTOSAVE=true;

const INPUT_STOP_TIMER	= 500;

var SAFE_MODE=true;
var WATCH=true;
var WATCH_SKIP=false;

const WATCH_PERIOD	= 1000;

const R_SUPER='r_super';
const R_VIEWANY='r_viewany';

const NR_VIEWNAME       = 1 << 0;
const NR_VIEWOTHER      = 1 << 1;
const NR_TAKE_IP        = 1 << 2;
const NR_EDIT_IP        = NR_TAKE_IP;
const NR_TAKE_VLAN        = NR_TAKE_IP;
const NR_EDIT_VLAN        = NR_TAKE_VLAN;
const NR_FREE_IP        = 1 << 3;
const NR_FREE_VLAN	= NR_FREE_IP;
const NR_IGNORE         = 1 << 4;
const NR_MAN_ACCESS     = 1 << 5; 
const NR_MAN_RANGES     = 1 << 6;
const NR_DROP_NET       = 1 << 7;
const NR_EDIT_NET       = 1 << 8;
const RR_TAKE_NET       = 1 << 9;
const RR_DENY_TAKE_IP   = 1 << 10; //also deny editing

const TICK_v4r          = "v4r";
const TICK_v6r          = "v6r";
const TICK_v4net        = "v4net";
const TICK_v6net        = "v6net";
const TICK_vd           = "vd";
const TICK_vlan         = "vlan";
const TICK_vr           = "vr";
const TICK_user         = "user";
const TICK_group        = "group";
const TICK_tp           = "tp";
const TICK_ic           = "ic";
const TICK_n4c          = "n4c";
const TICK_n6c          = "n6c";
const TICK_site         = "site";



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

const group_vlan_rights=Array(
  { "right": NR_VIEWNAME,
    "label_text": "Имен",
    "label_descr": "Просмотр наименований объектов"
  },
  { "right": NR_VIEWOTHER,
    "label_text": "Детл",
    "label_descr": "Просмотр детальной информации об объектах"
  },
  { "right": NR_TAKE_VLAN,
    "label_text": "ЗанVl",
    "label_descr": "Занятие VLAN/BD"
  },
  { "right": NR_EDIT_VLAN,
    "label_text": "РедVl",
    "label_descr": "Редактирование полей VLAN/BD"
  },
  { "right": NR_FREE_VLAN,
    "label_text": "УдлVl",
    "label_descr": "Освобождение VLAN/BD"
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

var watchTimer;
var watches={};

$.fn.moveToTop = function() {
  let z_index=1000;
  $(".ui-dialog").each(function() {
    let dz_index=Number($(this).css("zIndex"));
    if(!isNaN(dz_index) && dz_index > z_index) z_index = dz_index + 1;
  });

  this.css("zIndex", z_index);
  return this;
};


function watcherFunc() {
  watchTimer = undefined;
  if( $.isEmptyObject(watches) || !WATCH || WATCH_SKIP ) {
    watchTimer = setTimeout(watcherFunc, WATCH_PERIOD);
  } else {
    let w={};
    for(let subject in watches) {
      if(g_checks[subject] == undefined) { throw("Error"); };
      if(w[subject] == undefined) w[subject] = {};
      for(let id in watches[subject]) {
        if(g_checks[subject][id] == undefined) { throw("Error"); };
        w[subject][id] = g_checks[subject][id];
      };
    };

    $("#watch_debug").text(jstr(watches)+"\n"+jstr(w)+"\n"+( new Date().toLocaleTimeString('ru')));
    run_query({"action": "watch", "checks": w}, function(ret_data) {
      if(ret_data['ok']['result'] == 'ok' || WATCH_SKIP) {
        if(WATCH) {
          watchTimer = setTimeout(watcherFunc, WATCH_PERIOD);
        };
      } else {
        WATCH = false;
        let warn_cont=$(DIV)
         .css({"position": "fixed", "top": "0px", "left": "0px", "right": "0px", "height": "auto", "text-align": "center"})
         .moveToTop()
         .appendTo("BODY") 
        ;
        let warn=$(DIV)
         .css({"display": "inline-block", "background-color": "salmon", "border": "2px solid red", "padding": "1ema", "text-align": "left"})
         .appendTo( warn_cont )
        ;
        warn
         .append( $(DIV).text("Внимание, данные были изменены в стороннем сеансе и могут не соответствовать отображаемым прямо сейчас. Настоятельно рекомендуем обновить экран") )
        ;
        let table=$(TABLE)
         .append( $(TR)
           .append( $(TD).text("Пользователь") )
           .append( $(TD).text("Время крайнего изменения") )
         )
         .appendTo( warn )
        ;

        ret_data['ok']['users'].sort(function(a, b) { return Number(b['ts']) - Number(a['ts']); });

        for(let i=0; i < ret_data['ok']['users'].length; i++) {
          $(TR)
           .append( $(TD).text(ret_data['ok']['users'][i]['user_name']).title(ret_data['ok']['users'][i]['user_login']) )
           .append( $(TD).text(from_unix_time(ret_data['ok']['users'][i]['ts'])) )
           .appendTo( table )
          ;
        };
      };
    });
  };
};

function watch(subject, id) {
  if(g_checks[subject] == undefined) { throw("Unwatchable subject: "+subject+" id: "+id); };
  if(g_checks[subject][id] == undefined) { throw("Unwatchable subject: "+subject+" id: "+id); };
  if(watchTimer != undefined) { clearTimeout(watchTimer); watchTimer = undefined; };
  if(watches[subject] == undefined) { watches[subject] = {}; };
  if(watches[subject][id] == undefined) { watches[subject][id] = 0; };
  watches[subject][id]++;

  if(watches[subject][id] > 3) {
    throw("Error");
  };

  if(SAFE_MODE && WATCH) {
    watchTimer = setTimeout(watcherFunc, WATCH_PERIOD);
  };
};

function unwatch(subject, id) {
  if(subject == undefined) {
    if(watchTimer != undefined) { clearTimeout(watchTimer); watchTimer = undefined; };
    watches={};
    g_checks={};
    $("#watch_debug").text("none");
    return;
  };

  if(watches[subject] == undefined) {
    if(watchTimer != undefined) { clearTimeout(watchTimer); watchTimer = undefined; };
    throw("Error");
  };
  if(watches[subject][id] == undefined) {
    if(watchTimer != undefined) { clearTimeout(watchTimer); watchTimer = undefined; };
    throw("Error");
  };
  watches[subject][id] --;
  if(watches[subject][id] < 0) {
    if(watchTimer != undefined) { clearTimeout(watchTimer); watchTimer = undefined; };
    throw("Error");
  };
  if(watches[subject][id] == 0) {
    delete watches[subject][id];
    if( $.isEmptyObject(watches[subject]) ) {
      delete watches[subject];
      if( $.isEmptyObject(watches) ) {
        $("#watch_debug").text("none");
        if(watchTimer != undefined) {
          clearTimeout(watchTimer);
          watchTimer = undefined;
        };
      };
    };
  };
};

function any_icon(icon_str) {
  if(String(icon_str).match(/^ui-icon(?:-[a-z0-9]+)+$/)) {
    return $(LABEL)
     .addClass("ui-icon")
     .addClass( icon_str )
    ;
  } else if(String(icon_str).match(/^&#[xX]?[0-9a-fA-F]+;$/)) {
    return $(LABEL)
     .html( icon_str )
    ;
  } else if(String(icon_str).match(/\.(?:png|jpg|jpeg|ico|gif)$/)) {
    return $(IMG)
     .prop("src", icon_str )
    ;
  } else {
    return $(LABEL)
     .addClass("ui-icon")
     .addClass("ui-icon-alert")
     .addClass("wrong")
     .css({"color": "red"})
     .title("Неверное значение поля")
    ;
  };
};

function range_icon(icon_str) {
  if(String(icon_str).match(/^ui-icon(?:-[a-z0-9]+)+$/)) {
    return $(LABEL)
     .addClass("ui-icon")
     .addClass( icon_str )
    ;
  } else if(String(icon_str).match(/^&#[xX]?[0-9a-fA-F]+;$/)) {
    return $(LABEL)
     .html( icon_str )
    ;
  } else if(String(icon_str).match(/\.(?:png|jpg|jpeg|ico|gif)$/)) {
    return $(IMG)
     .prop("src", icon_str )
    ;
  } else {
    return $(LABEL)
     .addClass("ui-icon")
     .addClass("ui-icon-arrow-2-n-s")
    ;
  };
};

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

function has_nright(rmask, right) {
  if(has_right(R_SUPER)) return true;
  if((right === NR_VIEWNAME || right === NR_VIEWOTHER) && has_right(R_VIEWANY)) return true;
  return ((rmask & right) >>> 0) > 0;
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

function validate_vlan_range() {
  let start_input=$("INPUT#vlan_range_start");
  let stop_input=$("INPUT#vlan_range_stop");

  if(start_input.length != 1 || stop_input.length != 1) { error_at(); return false; };

  let start_vlan=start_input.val();
  let stop_vlan=stop_input.val();

  let valid=true;

  if(start_vlan === false && !start_vlan.match(/^\d+$/)) {
    start_input.animateHighlight(); valid=false;
  };
  if(stop_vlan === false && !stop_vlan.match(/^\d+$/)) {
    stop_input.animateHighlight(); valid=false;
  };

  if(valid && (start_vlan > stop_vlan)) {
    start_input.add(stop_input).animateHighlight(); valid=false;
  };

  return valid;
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

function take_vlan() {
  let vlan_number=$(this).data("vlan");
  if(vlan_number == undefined) { throw("error"); };

  let this_row=$(this).closest("TR");
  let input=this_row.find("INPUT.any_vlan");

  if(vlan_number == "from_input") {
    vlan_number = input.val();
    if(vlan_number == undefined) { throw("error"); };
    if(!String(vlan_number).match(/^\d+$/)) {
      input.animateHighlight("red", 300);
      return;
    };
  };

  vlan_number=Number(vlan_number);

  if(!String(vlan_number).match(/^\d+$/)) { throw("error"); };

  let tbody=$(this).closest("TBODY.vlans_list");
  let vd_id=tbody.data("vd_id");

  let check_row=tbody.find(".vlan_"+String(vlan_number));

  if(check_row.length > 0) {
    if(input.length == 0) {
      throw("error");
    };
    input.focus().add( check_row ).animateHighlight("red", 300);
    return;
  }; 

  let split_row;

  tbody.find(".vlan_take_row").each(function() {
    if($(this).data("vlan_start") <= vlan_number && $(this).data("vlan_stop") >= vlan_number) {
      split_row=$(this);
      return false;
    };
  });

  run_query({"action": "take_vlan", "vlan_number": vlan_number, "vd_id": vd_id}, function(ret_data) {
    /*let ret_data={"ok": { "vlan_id"      :     "newvlan_"+vlan_number,
                          "vlan_number"  : vlan_number,
                          "vlan_name"    : "VLAN_"+vlan_number,
                          "vlan_descr"   : "",
                          "vlan_fk_vd_id": "2",
                          "v4nets": null,
                          "v6nets": null
                        }
    };*/
    let rmask=0;
    if(split_row != undefined) {
      rmask=Number(split_row.data("rmask"));
    };

    let opts={ "opt": tbody.data("opt"), "presel": tbody.data("presel"), "donefunc": tbody.data("donefunc")};

    let vlan_row=vlans_vlan_row(ret_data['ok'], rmask, opts);
    if(split_row != undefined) {
      vlan_row.append( split_row.find(".vlan_ranges_td").clone(true) );
    } else {
      vlan_row.append( $(TD).addClass("vlan_ranges_td") );
    };

    if(split_row == undefined) {
      tbody.append( vlan_row );
      let prev_row=vlan_row.prev();
      let split_start;
      let split_stop;
      if(prev_row.length != 1) { throw("error"); };
      if(prev_row.hasClass("vlan_row")) {
        let prev_vlan=Number(prev_row.data("data")['vlan_number']);
        if(prev_vlan >= vlan_number) { throw("error"); };
        split_start=prev_vlan+1;
        if(split_start < vlan_number) {
          split_stop=vlan_number-1;
          let take_row=vlans_take_row(split_start, split_stop, rmask, opts);
	  take_row.append( $(TD).addClass("vlan_ranges_td") );
          take_row.insertBefore( vlan_row );
        };
      } else if(prev_row.hasClass("vlan_take_row")) {
        let prev_ranges_td=prev_row.find(".vlan_ranges_td");
        if(prev_ranges_td.hasClass("with_ranges")) {
          split_start=Number(prev_row.data("vlan_stop")) + 1;
          if(split_start > vlan_number) { throw("Error"); };
          if(split_start < vlan_number) {
            split_stop=vlan_number - 1;
            let take_row=vlans_take_row(split_start, split_stop, rmask, opts);
            take_row.append( $(TD).addClass("vlan_ranges_td") );
            take_row.insertBefore( vlan_row );
          };
        } else {
          split_start=Number(prev_row.data("vlan_start"));
          if(split_start >= vlan_number) { throw("Error"); };
          split_stop=vlan_number - 1;
          let take_row=vlans_take_row(split_start, split_stop, rmask, opts);
          take_row.append( prev_ranges_td.clone(true) );
          prev_row.replaceWith( take_row );
        };
      } else {
        throw("error");
      };
    } else {
      let split_start=Number(split_row.data("vlan_start"));
      let split_stop=Number(split_row.data("vlan_stop"));

      let take_before_row=undefined;
      let take_after_row=undefined;

      if(split_start != split_stop) {
        if(split_start == vlan_number) {
          split_start++;
          take_after_row=vlans_take_row(split_start, split_stop, rmask, opts);
          take_after_row.append( split_row.find(".vlan_ranges_td").clone(true) );
        } else if(split_stop == vlan_number) {
          split_stop--;
          take_before_row=vlans_take_row(split_start, split_stop, rmask, opts);
          take_before_row.append( split_row.find(".vlan_ranges_td").clone(true) );
        } else {
          take_before_row=vlans_take_row(split_start, vlan_number-1, rmask, opts);
          take_before_row.append( split_row.find(".vlan_ranges_td").clone(true) );

          take_after_row=vlans_take_row(vlan_number+1, split_stop, rmask, opts);
          take_after_row.append( split_row.find(".vlan_ranges_td").clone(true) );
        };
      };

      split_row.replaceWith( vlan_row );
      if(take_before_row != undefined) {
        take_before_row.insertBefore( vlan_row );
      };
      if(take_after_row != undefined) {
        take_after_row.insertAfter( vlan_row );
      };
    };
    if(typeof(vlan_row.get(0).scrollIntoViewIfNeeded) !== "undefined") {
      vlan_row.get(0).scrollIntoViewIfNeeded();
    } else {
      vlan_row.get(0).scrollIntoView();
    };
    if(input.length == 1) { input.val(""); };
    vlan_row.animateHighlight("lightgreen");
  });
};

function vlans_take_row(vlan_start, vlan_stop, rmask, opts) {
  if(opts == undefined) { throw("Error"); };
  let ret=$(TR).addClass("bg_colored")
   .addClass("vlan_take_row")
   .data("vlan_start", Number(vlan_start))
   .data("vlan_stop", Number(vlan_stop))
   .data("rmask", Number(rmask))
  ;


  if(opts['presel'] != undefined || (opts['opt'] != undefined && opts['opt']['return'] != undefined && opts['donefunc'] != undefined)) {
    ret.append( $(TD) );
  };

  let take_td=$(TD).prop("colspan", 3)
   .css({"position": "relative", "padding": "0.2em 0.5em"})
  ;

  if(has_right(R_SUPER)) {
    take_td
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-caret-1-nw")
       .addClass("ui-button")
       .addClass("vlan_range_btn")
       .css({"position": "absolute", "top": 0, "left": 0, "font-size": "49%"})
       .hide()
       .data("range_start", vlan_start)
       .title("Установить начало диапазона: "+vlan_start)
       .click(function(e) {
          e.stopPropagation();
          let _vlan=$(this).data("range_start");
          let z_index=Number($("#vlan_range_dialog").closest(".ui-dialog").css("zIndex"));
          $("#vlan_range_dialog").closest(".ui-dialog").css("zIndex", z_index+2);
          $("INPUT#vlan_range_start").val(_vlan).trigger("input");
       })
     )
    ;
  };

  if(has_nright(rmask, NR_TAKE_VLAN)) {

/*
    if(vlan_stop != vlan_start) {
      take_td
       .append( $(LABEL).text("Занять:")
         .css({"font-size": "initial", "padding": "0.1em 0.2em", "margin-left": "0.5em"})
       )
      ;
    } else {
      take_td
       .append( $(LABEL).text("Занять:")
         .css({"font-size": "initial", "padding": "0.1em 0.2em", "margin-left": "0.5em"})
       )
      ;
    };
*/
    take_td
     .append( $(LABEL).text(vlan_start)
       .addClass("ui-button")
       .title("Занять VLAN "+vlan_start)
       .css({"font-size": "initial", "padding": "0.1em 0.2em", "margin-left": "0.5em"})
       .data("vlan", Number(vlan_start))
       .click( take_vlan )
     )
    ;

    if(vlan_stop != vlan_start) {
      take_td
       .append( $(LABEL).text(" - ") )
       .append( $(LABEL).text(vlan_stop)
         .addClass("ui-button")
         .title("Занять VLAN "+vlan_stop)
         .css({"font-size": "initial", "padding": "0.1em 0.2em", "margin-left": "0.5em"})
         .data("vlan", Number(vlan_stop))
         .click( take_vlan )
       )
      ;
    };

    if(vlan_stop > (vlan_start + 1)) {
      take_td
       .append( $(LABEL).text(" - ") )
       .append( $(INPUT).css({"width": "4em"}).prop({"placeholder": "xxxx"}).addClass("any_vlan")
         .enterKey(function() {
           $(this).closest(".vlan_take_row").find(".take_btn").trigger("click");
         })
       )
       .append( $(LABEL)
         //.text("Занять произвольный")
         .addClass("ui-icon").addClass("ui-icon-plus")
         .title("Занять произвольный")
         .addClass("take_btn")
         .addClass("ui-button")
         .css({"font-size": "initial", "padding": "0.1em 0.2em", "margin-left": "0.5em"})
         .data("vlan", "from_input")
         .click( take_vlan )
       )
      ;
    };

  } else {
    take_td
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-locked")
       .css({"color": "gray"})
       .title("У вас недостаточно прав занимать VLAN в этом диапазоне")
     )
    ;
  };

  if(has_right(R_SUPER)) {
    take_td
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-caret-1-se")
       .addClass("ui-button")
       .addClass("vlan_range_btn")
       .css({"position": "absolute", "bottom": 0, "right": 0, "font-size": "49%"})
       .hide()
       .data("range_stop", vlan_stop)
       .title("Установить окончание диапазона: "+vlan_stop)
       .click(function(e) {
          e.stopPropagation();
          let _vlan=$(this).data("range_stop");
          let z_index=Number($("#vlan_range_dialog").closest(".ui-dialog").css("zIndex"));
          $("#vlan_range_dialog").closest(".ui-dialog").css("zIndex", z_index+2);
          $("INPUT#vlan_range_stop").val(_vlan).trigger("input");
       })
     )
    ;
  };

  ret.append( take_td );

  ret.append( $(TD) );

  return ret;
};

$.fn.vlan_click_edit = function(prop_name, style, validate_func) {
  this.data("prop_name", prop_name);
  this.data("style", style);
  this.data("validate_func", validate_func);
  this.title("Нажмите сюда для изменения")
  this.addClass("vlan_click_label")
  this.click(function(e) {
    let prev_val=$(this).text();
    let _prop_name=$(this).data("prop_name");
    let _style=$(this).data("style");
    let input=$(INPUT)
     .data("prop_name", _prop_name)
     .data("style", _style)
     .data("prev_val", prev_val)
     .data("validate_func", $(this).data("validate_func"))
     .addClass("vlan_click_edit")
     .addClass(_prop_name)
    ;
    if(_style != undefined) {
      input.css(_style);
    };
    input.val(prev_val);

    input
     .inputStop(INPUT_STOP_TIMER, function(e) {
       //tab keydown function
       let this_td=$(this).parent();
       let next_td;
       if(e.shiftKey) {
         next_td=this_td.prev();
       } else {
         next_td=this_td.next();
       };
       if(next_td.find(".vlan_click_label").length == 1) {
         next_td.find(".vlan_click_label").trigger("click");
       } else if(next_td.find(".vlan_click_edit").length == 1) {
         next_td.find(".vlan_click_edit").focus();
       };
       return false;
     })
     .on("input_stop", function() {
       if(!VLANS_AUTOSAVE) {
         return;
       };
       $(this).trigger("save");
     })
     .on("save", function() {
       let _this=$(this);
       _this.addClass("saving");
       let _validate_func=$(this).data("validate_func");
       let _value=$(this).val();
       let _prop_name=$(this).data("prop_name");
       if(_validate_func != undefined) {
         if(!_validate_func(_value, _prop_name)) {
           $(this).css({"background-color": "pink"}).animateHighlight();
           return;
         };
       };
       $(this).css({"background-color": "yellow"});

       let vlan_id=$(this).closest(".vlan_row").data("data")['vlan_id'];

       let query={"action": "set_vlan_prop", "prop_name": _prop_name, "value": _value, "vlan_id": vlan_id};
       run_query(query, function() {
         _this.css({"background-color": "palegreen"});
         _this.closest(".vlan_row").find(".undo_btn").show();
         _this.closest(".vlan_row").find(".undo_btn_placeholder").hide();
         _this.removeClass("unsaved");
         _this.removeClass("saving")
         _this.addClass("saved");
       });

     })
    ;

    $(this).closest(".vlan_row").find(".save_btn_paceholder").hide();
    $(this).closest(".vlan_row").find(".save_btn").show();

    $(this).replaceWith( input );

    if(! e.ctrlKey ) {
      input.focus();
    };

  });
  return this;
};

function vlans_vlan_row(vlan, rmask, opts) {
  let ret=$(TR).addClass("bg_colored")
   .addClass("vlan_"+vlan['vlan_number'])
   .addClass("vlan_row")
   .data("data", vlan)
   .data("rmask", rmask)
  ;

  if(opts == undefined) { throw("Error"); };

  let can_change_sel=opts['opt'] != undefined && opts['opt']['return'] != undefined && opts['donefunc'] != undefined;
  let presel = false;
  if(opts['presel'] != undefined) {
    if(typeof(opts['presel']) === "object") {
      presel = in_array(opts['presel'], vlan['vlan_id']);
    } else {
      presel = opts['presel'] == vlan['vlan_id'];
    };
  };
  if(opts['presel'] != undefined || can_change_sel) {
    let sel_td=$(TD);

    if(opts['opt']['return'] == 'one') {
      if(can_change_sel) {
        sel_td
         .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-select").addClass("ui-button")
           .title("Выбрать этот VLAN/BD и вернуться на предыдущий экран")
           .data("donefunc", opts['donefunc'])
           .click(function() {
             let data=$(this).closest(".vlan_row").data("data");
             let donefunc=$(this).data("donefunc");
             $(this).closest(".dialog_start").dialog("close");
             if(donefunc != undefined) {
               donefunc(data);
             };
           })
         )
        ;
      } else {
        sel_td
         .append( $(LABEL).addClass("ui-icon").addClass(presel?"ui-icon-check":"ui-icon-blank").addClass("ui-button")
           .title(presel?"Этот VLAN/BD выбран":"")
         )
        ;
      };
    } else {
      sel_td
       .append( $(INPUT).prop({"type": "checkbox", "checked": presel})
         .addClass("select_checkbox")
         .data("can_change_sel", can_change_sel)
         .click( function() { return $(this).data("can_change_sel"); })
         .on("change", function() {
           $(this).closest(".dialog_start").find(".vlans_list").trigger("sel_change");
         })
       )
      ;
    };
    if(presel) {
      sel_td.css({"background-color": "lightgreen"});
    };

    sel_td.appendTo( ret );
  };


  let num_td=$(TD)
   .css({"position": "relative", "padding-left": "0.9em"})
  ;

  if(_debug_opts) {
    num_td
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-info").css({"color": "lightgray", "font-size": "xx-small"})
       .title(jstr(vlan))
     )
    ;
  };

  if(has_right(R_SUPER)) {
    num_td
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-caret-1-nw")
       .addClass("ui-button")
       .addClass("vlan_range_btn")
       .css({"position": "absolute", "top": 0, "left": 0, "font-size": "49%"})
       .hide()
       .data("range_start", vlan['vlan_number'])
       .title("Установить начало диапазона: "+vlan['vlan_number'])
       .click(function(e) {
          e.stopPropagation();
          let _vlan=$(this).data("range_start");
          let z_index=Number($("#vlan_range_dialog").closest(".ui-dialog").css("zIndex"));
          $("#vlan_range_dialog").closest(".ui-dialog").css("zIndex", z_index+2);
          $("INPUT#vlan_range_start").val(_vlan).trigger("input");
       })
     )
    ;
  };
  num_td.append( $(SPAN).text(vlan['vlan_number']) );

  ret.append( num_td );

  let vlan_name_label=$(LABEL)
   .css({"background-color": "#EEEEEE", "border": "1px solid gray", "display": "inline-block", "min-width": "10em", "height": "1.2em"})
   .text(vlan['vlan_name'])
   .addClass("vlan_name")
  ;

  if(has_nright(rmask, NR_EDIT_VLAN)) {
    vlan_name_label
     .vlan_click_edit('vlan_name', {"min-width": "10em", "width": "10em"}, function(value, prop) {
       return String(value).match(/^[0-9a-zA-Z_]{1,64}$/);
     })
    ;
  };

  ret
   .append( $(TD).css({"padding-top": "3px", "vertical-align": "top"})
     .append( vlan_name_label )
   )
  ;

  let vlan_descr_label=$(LABEL)
   .css({"background-color": "#EEEEEE", "border": "1px solid gray", "display": "inline-block", "min-width": "20em", "height": "1.2em"})
   .text(vlan['vlan_descr'])
   .addClass("vlan_descr")
  ;

  if(has_nright(rmask, NR_EDIT_VLAN)) {
    vlan_descr_label
     .vlan_click_edit('vlan_descr', {"min-width": "20em", "width": "20em"})
    ;
  };

  ret
   .append( $(TD).css({"padding-top": "3px", "vertical-align": "top", "padding-right": "1em", "position": "relative"})
     .append( vlan_descr_label )
   )
  ;

  if(has_right(R_SUPER)) {
    ret.find(".vlan_descr").parent()
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-caret-1-se")
       .addClass("ui-button")
       .addClass("vlan_range_btn")
       .css({"position": "absolute", "bottom": 0, "right": 0, "font-size": "49%"})
       .hide()
       .data("range_stop", vlan['vlan_number'])
       .title("Установить окончание диапазона: "+vlan['vlan_number'])
       .click(function(e) {
          e.stopPropagation();
          let _vlan=$(this).data("range_stop");
          let z_index=Number($("#vlan_range_dialog").closest(".ui-dialog").css("zIndex"));
          $("#vlan_range_dialog").closest(".ui-dialog").css("zIndex", z_index+2);
          $("INPUT#vlan_range_stop").val(_vlan).trigger("input");
       })
     )
    ;
  };
  let act_td=$(TD).appendTo( ret );

  if(has_nright(rmask, NR_EDIT_VLAN)) {
    act_td
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-bullets").addClass("ui-button")
       .css({"color": color_table_buttons})
       .title("Изменить все поля")
       .click(function() {
         let ev = jQuery.Event("click");
         ev.ctrlKey = true;
         $(this).closest(".vlan_row").find(".vlan_name").trigger("click");
         $(this).closest(".vlan_row").find(".vlan_descr").trigger(ev);
       })
     )
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-blank")
       .addClass("undo_btn_placeholder")
     )
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-arrowrefresh-1-s").addClass("ui-button")
       .addClass("undo_btn")
       .title("Отменить изменения")
       .css({"color": "green"})
       .hide()
       .click(function() {
         let prev_row=$(this).closest(".vlan_row");
         let _vlan=prev_row.data("data");
         let _rmask=prev_row.data("rmask");
         let query={"action": "save_vlan", "vlan_id": _vlan['vlan_id'], "vlan_name": _vlan['vlan_name'], "vlan_descr": _vlan['vlan_descr']};

         let tbody=prev_row.closest("TBODY");
         let opts={ "opt": tbody.data("opt"), "presel": tbody.data("presel"), "donefunc": tbody.data("donefunc") };

         run_query(query, function(ret_data) {
           let new_row=vlans_vlan_row(ret_data['ok'], _rmask, opts);
           new_row.append( prev_row.find(".vlan_ranges_td").clone() );
           prev_row.replaceWith( new_row );
         });
       })
     )
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-blank")
       .addClass("save_btn_placeholder")
     )
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-disk").addClass("ui-button")
       .addClass("save_btn")
       .title("Сохранить изменения")
       .css({"color": "green"})
       .hide()
       .click(function() {
         let _row=$(this).closest(".vlan_row");
         _row.find(".vlan_click_edit").trigger("save");
       })
     )
    ;
  };

  if(has_nright(rmask, NR_FREE_VLAN)) {
    act_td
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-trash").addClass("ui-button")
       .css({"color": "coral", "margin-left": "0.5em"})
       .title("Освободить VLAN "+vlan['vlan_number'])
       .click(function(e) {
         let vlan_row=$(this).closest(".vlan_row");
         let vlan_number=Number(vlan_row.data("data")['vlan_number']);
         let vlan_id=vlan_row.data("data")['vlan_id'];

         let tbody=$(this).closest("TBODY");
         let opts={ "opt": tbody.data("opt"), "presel": tbody.data("presel"), "donefunc": tbody.data("donefunc") };

         show_confirm_checkbox("Подтвердите удаление VLAN/BD "+vlan_number, function() {
           run_query({"action": "free_vlan", "vlan_id": vlan_id}, function() {
             // remove row from table and insert TAKE ranges
             let ranges_td=vlan_row.find(".vlan_ranges_td");
             let rmask=Number(vlan_row.data("rmask"));
             let new_row=vlans_take_row(vlan_number, vlan_number, rmask, opts);
             new_row.append( ranges_td.clone() );
             vlan_row.replaceWith( new_row );
           });
         }, undefined, undefined, e.shiftKey);
       })
     )
    ;
  };

  return ret;
};

function vlan_range_dialog(vr_id, donefunc) {
  if(vr_id == undefined && donefunc == undefined) { error_at(); return; };
  if( $("#vlan_range_dialog").length != 0) {
    let z_index=Number($("#vlan_range_dialog").closest(".ui-dialog").css("zIndex"));
    $("#vlan_range_dialog").closest(".ui-dialog").css("zIndex", z_index+2);
    return;
  };

  $(".vlan_range_btn").show();

  let title;

  if(vr_id == undefined) {
    title = "Добавление диапазона VLAN";
  } else {
    if(donefunc == undefined) {
      title = "Просмотр диапазона VLAN";
    } else {
      title = "Редактирование диапазона VLAN";
    };
  };

  let dialog=$(DIV).myid("vlan_range_dialog")
   .data("id", vr_id)
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
      let _id=$(this).data("id");
      if(_id != undefined) unwatch(TICK_vr, _id);
      unwatch(TICK_group, 0);
      $(".vlan_range_btn").hide();
      $(this).dialog("destroy");
      $(this).remove();
    }
  };

  if(has_right(R_SUPER)) {
    d['buttons'].push({
      "text": (vr_id == undefined?"Создать":"Сохранить"),
      "click": function() {
        let _sel=$("#vlans_list").find("SELECT.domain_sel");
        if(_sel.length == 0) return;
        let vd_id=_sel.val();
        if(vd_id == "") { return };
        if(vd_id == undefined) { throw("error"); };
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
            if(in_array(groups, gr_id)) { throw("Error"); };
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

        if(!validate_vlan_range()) return;

        let range_start=$("INPUT#vlan_range_start").val();
        let range_stop=$("INPUT#vlan_range_stop").val();

        let range_name=$("INPUT#vlan_range_name").val();
        let range_descr=$("TEXTAREA#vlan_range_descr").val();

        let range_style=$("INPUT#vlan_range_style").val();
        if(!validate_json(range_style)) {
          $("INPUT#vlan_range_style").animateHighlight();
          return;
        };

        let range_icon=$("INPUT#vlan_range_icon").val();
        let range_icon_style=$("INPUT#vlan_range_icon_style").val();
        if(!validate_json(range_icon_style)) {
          $("INPUT#vlan_range_icon_style").animateHighlight();
          return;
        };

        let query={"range_start": range_start, "range_stop": range_stop,
                   "range_name": range_name, "range_descr": range_descr,
                   //"range_visible": $("INPUT#vlan_range_invisible").is(":checked")?0:1,
                   "range_style": range_style, "range_icon": range_icon, "range_icon_style": range_icon_style,
                   "groups_rights": groups_rights
        };

        if(vr_id == undefined) {
          query['action'] = "vlan_add_range";
          query['vd_id']=vd_id;
        } else {
          query['action'] = "vlan_edit_range";
          query['range_id'] = vr_id;
        };

        run_query(query, function(data) {
          $(_this).dialog("close");
          if(donefunc != undefined) donefunc(data['ok']);
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
       .append( $(INPUT).myid("vlan_range_start").prop({"placeholder": "xxxx", "readonly": !has_right(R_SUPER)})
         .on("change input", validate_vlan_range)
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Окончание:") )
     )
     .append( $(TD)
       .append( $(INPUT).myid("vlan_range_stop").prop({"placeholder": "xxxx", "readonly": !has_right(R_SUPER)})
         .on("change input", validate_vlan_range)
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Наименование:") )
     )
     .append( $(TD)
       .append( $(INPUT).myid("vlan_range_name").prop({"placeholder": "Краткое наименование", "readonly": !has_right(R_SUPER)})
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Описание:") )
     )
     .append( $(TD)
       .append( $(TEXTAREA).myid("vlan_range_descr").prop({"readonly": !has_right(R_SUPER)})
       )
     )
   )
/*   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Скрытый:") )
     )
     .append( $(TD)
       .append( $(INPUT).myid("vlan_range_invisible").prop({"type": "checkbox"})
         .click(function() { return has_right(R_SUPER); })
       )
     )
   )*/
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Стиль линии/текста (JSON):") )
     )
     .append( $(TD)
       .append( $(INPUT).myid("vlan_range_style").prop({"placeholder": "{\"color\": \"red\"}", "readonly": !has_right(R_SUPER)})
         .val("{}")
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
       .append( $(INPUT).myid("vlan_range_icon").prop({"placeholder": "ui-icon-info", "readonly": !has_right(R_SUPER)})
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Стиль значка (JSON):") )
     )
     .append( $(TD)
       .append( $(INPUT).myid("vlan_range_icon_style").prop({"placeholder": "{\"color\": \"red\"}", "readonly": !has_right(R_SUPER)})
         .val("{}")
         .on("change input", function() { validate_json_elm.call(this, "lightgreen", "red"); })
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Права доступа:") )
     )
     .append( $(TD)
       .append( $(DIV).myid("vlan_range_rights") 
       )
       .append( $(DIV)
         .append( !has_right(R_SUPER)?$(LABEL):$(LABEL).addClass("ui-icon").addClass("ui-icon-plusthick").addClass("ui-button")
           .css({"color": color_table_buttons})
           .title("Добавить группу")
           .click(function() {
             let allow_add=true;
             $("DIV#vlan_range_rights").find(".group_rights_div").find(".group")
              .each(function() { if($(this).data("id") == undefined) { allow_add=false; return false; }; })
             ;
             if(allow_add) {
               $("DIV#vlan_range_rights").append( group_net_right_div(group_vlan_rights, undefined, (NR_VIEWNAME | NR_VIEWOTHER | NR_TAKE_VLAN | NR_EDIT_VLAN | NR_FREE_VLAN) >>> 0, {"allow_edit": true, "allow_delete": true}) );
             };
           })
         )
       )
     )
   )
  ;

  table.appendTo( dialog );

  dialog.dialog(d);

  if(vr_id != undefined) {
    let query={"action": "vlan_get_range", "range_id": vr_id};
    run_query(query, function(data) {
      $("INPUT#vlan_range_start").val(data['ok']['range_info']['vr_start']);
      $("INPUT#vlan_range_stop").val(data['ok']['range_info']['vr_stop']);

      if(data['ok']['range_info']['vr_name'] == "hidden") {
        $("INPUT#vlan_range_name").val("Скрыто").css({"color": "gray"});
      } else {
        $("INPUT#vlan_range_name").val(data['ok']['range_info']['vr_name']);
      };

      if(data['ok']['range_info']['vr_descr'] == "hidden") {
        $("TEXTAREA#vlan_range_descr").val("Скрыто").css({"color": "gray"});
      } else {
        $("TEXTAREA#vlan_range_descr").val(data['ok']['range_info']['vr_descr']);
      };

      //$("INPUT#vlan_range_invisible").prop("checked", Number(data['ok']['range_info']['vr_visible']) == 0);

      $("INPUT#vlan_range_style").val(data['ok']['range_info']['vr_style']);
      $("INPUT#vlan_range_icon").val(data['ok']['range_info']['vr_icon']);
      $("INPUT#vlan_range_icon_style").val(data['ok']['range_info']['vr_icon_style']);

      for(let i=0; i < data['ok']['range_group_rights'].length; i++) {
        $("DIV#vlan_range_rights").append( group_net_right_div(group_vlan_rights, data['ok']['range_group_rights'][i], (NR_VIEWNAME | NR_VIEWOTHER | NR_TAKE_VLAN | NR_EDIT_VLAN | NR_FREE_VLAN) >>> 0, { "allow_edit": has_right(R_SUPER), "allow_delete": has_right(R_SUPER)}) );
      };

      watch(TICK_vr, vr_id);
      watch(TICK_group, 0);
    });
  } else {
    run_query({"action": "get_groups"}, function() {
      watch(TICK_group, 0);
    });
  };

};


function vr_info() {
  let vr_info=$("#vr_info");
  if(vr_info.length == 0) {
    vr_info=$(DIV).myid("vr_info")
     .css({"background-color": "white", "border": "1px solid gray", "padding": "0.5em", "white-space": "pre"})
    ;

    $(DIV).myid("vr_info_parent")
     .css({"display": "inline-block", "position": "fixed", "bottom": "1em", "right": "1em", "z-index": 1000001})
     .append( $(DIV)
       .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-close").addClass("ui-button")
         .click(function() {
           $("#vr_info_parent").remove();
         })
       )
     )
     .append( vr_info )
     .appendTo("BODY")
    ;
  };

  vr_info.empty();

  let data=$(this).data("data");

  if(_debug_opts) {
    vr_info
     .append( $(LABEL)
       .addClass("ui-icon").addClass("ui-icon-info").css({"color": "lightgray", "font-size": "xx-small"})
       .title(jstr(data))
     ) 
    ;
  };

  let style;
  let icon_style;

  try {
    style=JSON.parse(data['vr_style']);
  } catch(err) {
    style={};
  };

  try {
    icon_style=JSON.parse(data['vr_icon_style']);
  } catch(err) {
    icon_style={};
  };

  let icon=range_icon(data['vr_icon'])
   .css( icon_style )
   .css(s_ranges_spacing)
   .title( data['vr_descr'] )
  ;

  vr_info.append( icon );

  vr_info
   .append( $(LABEL).text(data['vr_start']+" - "+data['vr_stop'])
     .css( style )
     .css({"margin-left": "1em"})
  );

  vr_info
   .append( $(LABEL).text(data['vr_name'])
     .css({"margin-left": "1em"})
     .title( data['vr_descr'] )
   )
  ;

  let rspan=$(SPAN).css({"white-space": "pre"});

  for(let i=0; i < group_vlan_rights.length; i++) {
    let rlabel=$(LABEL)
     .text(group_vlan_rights[i]['label_text'])
     .title(group_vlan_rights[i]['label_descr'])
     .data("right", group_vlan_rights[i]['right'])
     .css({"border": "1px solid gray", "padding": "0.1em", "font-size": "x-small", "margin-left": "0.3em"})
    ;

    if(has_nright(data['rmask'], group_vlan_rights[i]['right'])) {
      rlabel.css({"background-color": "lightgreen"});
    } else {
      rlabel.css({"background-color": "lightgray"});
    };

    rspan.append( rlabel );
  };

  vr_info.append( rspan );

  let can_edit=has_right(R_SUPER);

  vr_info
   .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-bullets").addClass("ui-button")
     .data("id", data['vr_id'])
     .css({"margin-left": "1em", "color": color_table_buttons })
     .title(can_edit?"Изменить":"Просмотр")
     .click(function() {
       let _id=$(this).data('id');
       if(_id == undefined) { error_at(); return; };

       $(".range_btn").show();
       let table_div=$("#vlans_list").find(".table_div");
       vlan_range_dialog(_id, can_edit?(function() {
         let scroll=table_div.scrollTop();
         table_div.data("scroll", scroll);

         $("#vlans_list").find("SELECT.domain_sel").trigger("change");
       }):undefined);
     })
   )
  ;

  if(can_edit) {
    vr_info
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-trash").addClass("ui-button")
       .css({"margin-left": "0.5em", "color": "coral"})
       .title("Удалить")
       .data("id", data['vr_id'])
       .click(function() {
         let _id=$(this).data('id');
         if(_id == undefined) { error_at(); return; };

         let table_div=$("#vlans_list").find(".table_div");

         show_confirm("Подтвердите удаление диапазона VLAN", function() {
           let query={"action": "vlan_delete_range", "range_id": _id};
           run_query(query, function() {
             let scroll=table_div.scrollTop();
             table_div.data("scroll", scroll);

             $("#vlans_list").find("SELECT.domain_sel").trigger("change");
           });
         });
       })
     )
    ;
  };

  if(data['vr_descr'] != "") {
    vr_info
     .append( $(DIV).text( data['vr_descr'] )
       .css({"padding": "0.5em", "background-color": "#FFFFEE"})
     )
    ;
  };

};

function vlans_ranges_td(vrs, current_ranges, vlans_display) {
  let ret=$(TD).css({"white-space": "pre"})
   .addClass("vlan_ranges_td")
  ;

  let ranges_count=0;
  for(let r in vrs) {
    let label=$(LABEL).css({"display": "inline-block", "width": "1em"});
    let added=false;
    if(current_ranges[r] != undefined) {
      if(vlans_display != undefined && vlans_display['range_start'][r] != undefined) {
        label.html("&#x2533;");
      } else if(vlans_display != undefined && vlans_display['range_stop'][r] != undefined) {
        label.html("&#x253B;");
      } else {
        label.html("&#x2503;");
      };
      added=true;
    };
    if(vlans_display != undefined && vlans_display['range_start_stop'][r] != undefined) {
      if(added) { throw("error"); };
      label.html("&#x25C0;");
      added=true;
    };
    
    if(added) {
      try {
        let vr_style=JSON.parse(vrs[r]['vr_style']);
        label.css(vr_style);
      } catch(e) {
        //just ignore
      };

      label.data("data", vrs[r]);
      label.title(vrs[r]['vr_name']);
      label.click(function() {
        vr_info.call(this);
      });
      label.dblclick(function(e) {
        e.stopPropagation();
        let _id=$(this).data("data")['vr_id'];
        let can_edit=has_right(R_SUPER);
        if(can_edit) $(".vlan_range_btn").show();
        let table_div=$("#vlans_list").find(".table_div");
        vlan_range_dialog(_id, can_edit?(function() {
          let scroll=table_div.scrollTop();

          table_div.data("scroll", scroll);
          $("#vlans_list").find("SELECT.domain_sel").trigger("change");
        }):undefined);
      });
      

      ranges_count++;
    };
    label.appendTo( ret );
  };

  if(ranges_count > 0) {
    ret.addClass("with_ranges");
  };

  if(_debug_opts) {
    ret
     .append( $(LABEL)
       .addClass("ui-icon").addClass("ui-icon-info").css({"color": "lightgray", "font-size": "xx-small"})
       .title(jstr({"current_ranges": current_ranges, "vlans_display": vlans_display}))
     ) 
    ;
  };
  return ret;
};

function populate_vlans_table(tbody, data) {
  let vlans=data['vlans'];
  let vd=data['vd'];
  let vrs=data['vrs'];

  let max_vlan=Number(vd['vd_max_num']);
  if(vlans.length > 0 && Number(data['vlans_stop']) > max_vlan) {
    max_vlan=Number(data['vlans_stop']);
  };

  let opts={ "opt": tbody.data("opt"), "presel": tbody.data("presel"), "donefunc": tbody.data("donefunc")};

  let vlans_display={};

  for(let i in vrs) {
    let rstart=Number(vrs[i]['vr_start']);
    let rstop=Number(vrs[i]['vr_stop']);
    if(vlans_display[rstart] == undefined) {
      vlans_display[rstart] = {'range_start': {}, 'range_stop': {}, 'range_start_stop': {}, 'vlan': undefined};
    };
    if(vlans_display[rstop] == undefined) {
      vlans_display[rstop] = {'range_start': {}, 'range_stop': {}, 'range_start_stop': {}, 'vlan': undefined};
    };
    if(rstart != rstop) {
      vlans_display[rstart]['range_start'][i] = true;
      vlans_display[rstop]['range_stop'][i] = true;
    } else {
      vlans_display[rstart]['range_start_stop'][i] = true;
    };
  };

  for(let i in vlans) {
    let vlan=vlans[i];
    let vlan_num=Number(vlan['vlan_number']);
    if(vlans_display[vlan_num] == undefined) {
      vlans_display[vlan_num] = {'range_start': {}, 'range_stop': {}, 'range_start_stop': {}, 'vlan': i};
    } else {
      vlans_display[vlan_num]['vlan'] = i;
    };
  };

  let vlan_keys=keys(vlans_display);
  vlan_keys.sort(function(a,b) { return Number(vlan_keys[a]) - Number(vlan_keys[b]); });

  let last_vlan=0;

  let current_ranges={};

  for(let i=0; i < vlan_keys.length; i++) {
    let vlan_key=vlan_keys[i];
    let vlan=vlans[vlan_key];
    let vlan_number=Number(vlan_key);

    if(vlan_number < 1) { throw("Error"); };

    if((last_vlan + 1) < vlan_number) {
      //we have to add TAKE row before adding this one
      let take_start=last_vlan + 1;
      let take_stop=vlan_number - 1;

      let take_effective_rmask = 0;
      for(let r in current_ranges) {
        take_effective_rmask = (take_effective_rmask | vrs[r]['rmask']) >>> 0;
      };

      let row=vlans_take_row(take_start, take_stop, take_effective_rmask, opts);
      row.append( vlans_ranges_td(vrs, current_ranges) );
      tbody.append( row );
    };

    for(let r in vlans_display[vlan_key]["range_start"]) {
      if(current_ranges[r] != undefined) { throw("error"); };
      current_ranges[r]=true;
    };

    let row;

    let vlan_effective_rmask = 0;
    for(let r in current_ranges) {
      vlan_effective_rmask = (vlan_effective_rmask | vrs[r]['rmask']) >>> 0;
    };


    if(vlans_display[vlan_key]["vlan"] != undefined) {
      row=vlans_vlan_row(vlan, vlan_effective_rmask, opts);
    } else {
      row=vlans_take_row(vlan_number, vlan_number, vlan_effective_rmask, opts);
    };

    row.append( vlans_ranges_td(vrs, current_ranges, vlans_display[vlan_key] ));

    tbody.append( row );

    last_vlan=vlan_number;

    for(let r in vlans_display[vlan_key]["range_stop"]) {
      if(current_ranges[r] == undefined) { throw("error"); };
      delete current_ranges[r];
    };
  };

  if(keys(current_ranges).length != 0 ) { throw("error "+jstr(current_ranges)); };

  if(last_vlan  < max_vlan) {
    //we have to add TAKE row at the end
    let take_start=last_vlan + 1;
    let take_stop=max_vlan;

    let row=vlans_take_row(take_start, take_stop, 0, opts);
    row.append( vlans_ranges_td(vrs, current_ranges) );
    tbody.append( row );
  };

};

function vdomain_row(vdomain) {
  return $(OPTION)
   .data("data", vdomain)
   .text(vdomain['vd_name'])
   .val(vdomain['vd_id'])
  ;
};

function vdomain_edit(vd_id, opt, donefunc) {
  if(opt == undefined) { error_at(); return; };
  if( $("#vdomain_edit").length != 0) { return; };
  if(!has_right(R_SUPER) && vd_id == undefined) { error_at(); return; };
  if(donefunc == undefined && vd_id == undefined) { error_at(); return; };

  let readonly= !has_right(R_SUPER);

  let dialog=$(DIV).myid("vdomain_edit")
   .data("opt", opt)
   .data("id", vd_id)
   .data("donefunc", donefunc)
   .addClass("dialog_start")
   .title(has_right(R_SUPER)?(vd_id != undefined?"Редактирование домена VLAN/BD":"Создание домена VLAN/BD"):"Просмотр домена VLAN/BD")
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
      let _id=$(this).data("id");
      if(_id != undefined) { unwatch(TICK_vd, _id); };
      $(this).dialog("destroy");
      $(this).remove();
    },
  };

  if(has_right(R_SUPER)) {
    d['buttons'].push({ "text": vd_id == undefined?"Создать":"Сохранить", "class": "confirm_btn", "click": function() {
      let _dialog=$(this);
      let _vd_name=_dialog.find(".vd_name").val().trim();
      if(_vd_name == undefined) { error_at(); return; };
      if(!_vd_name.match(/\S/)) {
        _dialog.find(".vd_name").animateHighlight();
        return;
      };
      let _vd_max_num=_dialog.find(".vd_max_num").val().trim();
      if(_vd_max_num == undefined) { error_at(); return; };
      if(!_vd_max_num.match(/^\d+$/)) {
        _dialog.find(".vd_max_num").animateHighlight();
        return;
      };
      let _vd_descr=_dialog.find(".vd_descr").val();
      if(_vd_descr == undefined) { error_at(); return; };

      let query={"vd_name": _vd_name, "vd_descr": _vd_descr, "vd_max_num": _vd_max_num};

      let _id=_dialog.data("id");
      if(_id == undefined) {
        query['action'] = 'add_vdomain';
      } else {
        query['action'] = 'edit_vdomain';
        query['vd_id'] = _id;
      };

      let _donefunc=_dialog.data("donefunc");

      run_query(query, function(ret_data) {
        _dialog.dialog("close");
        if(_donefunc != undefined) {
          _donefunc(ret_data['ok']);
        };
      });
    }});
  };

  d['buttons'].push({ "text": "Закрыть", "click": function() { $(this).dialog( "close" ); } });

  dialog
   .append( $(TABLE)
     .append( $(TR)
       .append( $(TD).css({"text-align": "rigth"})
         .append( $(LABEL).text("Имя: ") )
       )
       .append( $(TD)
         .append( $(INPUT).addClass("vd_name").prop({"readonly": readonly}) )
       )
     )
     .append( $(TR)
       .append( $(TD).css({"text-align": "rigth"})
         .append( $(LABEL).text("Макс. номер: ") )
       )
       .append( $(TD)
         .append( $(INPUT).addClass("vd_max_num").prop({"readonly": readonly}).val("4095") )
       )
     )
     .append( $(TR)
       .append( $(TD).css({"text-align": "rigth"})
         .append( $(LABEL).text("Описание: ") )
       )
       .append( $(TD)
         .append( $(TEXTAREA).addClass("vd_descr").prop({"readonly": readonly}) )
       )
     )
   )
  ;

  if(vd_id != undefined) {
    run_query({"action": "get_vdomain", "vd_id": vd_id}, function(ret_data) {
      dialog.find(".vd_name").val(ret_data['ok']['vd_name']);
      dialog.find(".vd_max_num").val(ret_data['ok']['vd_max_num']);
      dialog.find(".vd_descr").val(ret_data['ok']['vd_descr']);
      dialog.data("data", ret_data['ok']);
      watch(TICK_vd, vd_id);
    });
  };

  dialog.dialog(d);
};

function vlans_list(presel_vlan_id, opt, donefunc) {
  if(opt == undefined) { error_at(); return; };
  if( $("#vlans_list").length != 0) { return; };

  let dialog=$(DIV).myid("vlans_list")
   .data("opt", opt)
   .data("donefunc", donefunc)
   .data("presel_id", presel_vlan_id)
   .addClass("dialog_start")
   .title(donefunc != null?"Выбор VLAN/BD":"Просмотр VLAN/BD")
   .css({"white-space": "pre", "font-size": "larger"})
   .appendTo("BODY")
  ;

  if(_debug_opts) {
    dialog
     .append( $(LABEL)
       .addClass("ui-icon").addClass("ui-icon-info")
       .css({"position": "absolute", "display": "inline-block", "color": "lightgray", "left": "0.2em"})
       .title(jstr(opt))
       .click(function() {
         let sp=$(this).closest(".dialog_start").find(".table_div").scrollTop();
         $("#debug").text(sp);
       })
     )
    ;
  };

  let d={
    modal:true,
    position: { my: "center top", at: "center top", of: window },
    maxHeight: $(window).height(),
    minHeight: $(window).height()-10,
    minWidth:1000,
    buttons: [],
    open: function() {
    },
    close: function() {
      unwatch(TICK_vd, 0);
      let _sel_id=$(this).find("SELECT.domain_sel").val();
      if(_sel_id != "") {
        unwatch(TICK_vd, _sel_id);
      };
      $(this).dialog("destroy");
      $(this).remove();
      $("#vr_info_parent").remove();
    },
  };

  if(donefunc != undefined && (opt['return'] == 'any' || opt['return'] == 'many')) {
    d['buttons'].push({ "text": "Выбрать", "class": "confirm_btn", "click": function() {
      let _dialog=$(this);
      let _opt=_dialog.data("opt");
      let tbody=_dialog.find(".vlans_list");

      let vlans=Array();

      tbody.find(".vlan_row").each(function() {
        let vlan=$(this).data("data");
        if($(this).find(".select_checkbox").is(":checked")) {
          vlans.push(vlan);
        };
      });

      if(_opt['return'] == 'many' && vlans.length == 0) {
        $(this).dialog("widget").find("BUTTON.confirm_btn").animateHighlight();
        return;
      };

      let _donefunc=$(this).data("donefunc");
      $(this).dialog("close");
      _donefunc(vlans);
    }});
  };

  d['buttons'].push({ "text": has_right(R_SUPER)?"Отменить":"Закрыть", "click": function() { $(this).dialog( "close" ); } });

  let domain_sel=$(SELECT).addClass("domain_sel")
   .title("")
   .append( $(OPTION).text("Выберете домен ...").val("") )
   .on("change select", function() {
     $("#vr_info_parent").remove();
     let _dialog=$(this).closest(".dialog_start");
     let _opt=_dialog.data("opt");
     let _sel=$(this);
     let _sel_id=_sel.val();
     let _opt_elm=_sel.find("OPTION:selected");

     let _prev_id=$(this).data("prev_id");

     if(_prev_id != undefined) {
       if(_prev_id != "") unwatch(TICK_vd, _prev_id);
     };
     $(this).data("prev_id", _sel_id);

     if(_sel_id != undefined && _sel_id != "") {
       _sel.title(_opt_elm.data("data")['vd_descr']);
       _dialog.find(".vdomain_edit_btn").show();
       if(_opt_elm.data("data")['vlans_count'] > 0) {
         _dialog.find(".vdomain_delete_btn").hide();
       } else {
         _dialog.find(".vdomain_delete_btn").show();
       };
     } else {
       _dialog.find(".vdomain_edit_btn").hide();
       _dialog.find(".vdomain_delete_btn").hide();
       _sel.title("");
     };

     let _tbody=_dialog.find(".vlans_list").empty().data("vd_id", _sel_id);

     if(_sel_id != undefined && _sel_id != "") {
       let query={"action": "get_vlans", "vd_id": _sel_id};
       run_query(query, function(ret_data) {
         populate_vlans_table(_tbody, ret_data['ok'], _opt);
         let table_div=$("#vlans_list").find(".table_div");
         let scroll=table_div.data("scroll");
         if(scroll != undefined) {
           table_div.data("scroll", undefined);
         };
         table_div.scrollTop(scroll);
         _tbody.trigger("sel_change");
         watch(TICK_vd, _sel_id);
       });
     } else { 
       _tbody.append( $(TR).append( $(TD).prop("colaspan", 99).text("Выберете домен") ) );
       _tbody.trigger("sel_change");
     };


   })
  ;

  let head_row=$(DIV)
   .css({"position": "absolute", "top": "1em", "left": "1em", "right": "1em"})
   .append( $(LABEL).text("Домен: ") )
   .append( domain_sel )
  ;

  if(has_right(R_SUPER)) {
    head_row
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-plusthick").addClass("ui-button")
       .css({"margin-left": "0.5em", "color": color_table_buttons})
       .click(function() {
         let _sel=$(this).closest(".dialog_start").find(".domain_sel");
         vdomain_edit(undefined, {}, function(ret_data) {
           let row=vdomain_row(ret_data);
           row.appendTo( _sel );
           _sel.val(ret_data['vd_id']).trigger("change");
         })
       })
     )
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-bullets").addClass("ui-button").addClass("vdomain_edit_btn")
       .css({"margin-left": "0.5em", "color": color_table_buttons})
       .click(function() {
         let _sel=$(this).closest(".dialog_start").find(".domain_sel");
         let prev_row=_sel.find("OPTION:selected");
         if(_sel.val() == "") return;
         if(_sel.val() != prev_row.val() ) { error_at(); return; };
         vdomain_edit(prev_row.val(), {}, function(ret_data) {
           let row=vdomain_row(ret_data);
           prev_row.replaceWith(row);
           _sel.val(ret_data['vd_id']);
           _sel.title(ret_data['vd_descr']);
         })
       })
       .hide()
     )
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-trash").addClass("ui-button").addClass("vdomain_delete_btn")
       .css({"margin-left": "0.5em", "color": "coral"})
       .click(function() {
         let _sel=$(this).closest(".dialog_start").find(".domain_sel");
         let prev_row=_sel.find("OPTION:selected");
         if(_sel.val() == "") return;
         if(_sel.val() != prev_row.val() ) { error_at(); return; };

         show_confirm_checkbox("Подтвердите удаление домена.\nВНИМАНИЕ! Будут удалены связаные с доменом диапазоны VLAN!", function() {
           run_query({"action": "delete_vdomain", "vd_id": prev_row.val()}, function(ret_data) {
             prev_row.remove();
             _sel.val("").trigger("change");
           })
         });

         
       })
       .hide()
     )
    ;
  };

  head_row
   .append( $(SPAN).css({"white-space": "pre", "float": "right"})
     .append( $(LABEL).prop("for", "vlans_autosave").text("Автосохранение: ")
       .title("Автосохранение данных")
     )
     .append( $(INPUT).myid("vlans_autosave").prop({"type": "checkbox", "checked": VLANS_AUTOSAVE})
       .on("change", function() {
         VLANS_AUTOSAVE=$(this).is(":checked");
       })
     )
   )
  ;

  dialog.append( head_row );

  let table_div=$(DIV)
   .addClass("table_div")
   .css({"position": "absolute", "top": "3em", "left": "1em", "right": "1em", "bottom": "1em", "overflow-y": "scroll"})
  ;

  dialog.append( table_div );

  let head_tr=$(TR).css({"position": "relative"});

  if( presel_vlan_id != undefined || (opt != undefined && opt['return'] != undefined && donefunc != undefined)) {
    head_tr
     .append( $(TH).text("")
       .css({"position": "sticky", "top": "0", "background-color": "white", "z-index": 1, "border-bottom": "1px solid gray", "border-right": "1px solid gray"})
     )
    ;
  };
  head_tr
   .append( $(TH).text("VLAN/BD")
     .css({"position": "sticky", "top": "0", "background-color": "white", "z-index": 1, "border-bottom": "1px solid gray", "border-right": "1px solid gray"})
   )
   .append( $(TH).text("Краткое имя")
     .css({"position": "sticky", "top": "0", "background-color": "white", "z-index": 1, "border-bottom": "1px solid gray", "border-right": "1px solid gray"})
   )
   .append( $(TH).text("Описание")
     .css({"position": "sticky", "top": "0", "background-color": "white", "z-index": 1, "border-bottom": "1px solid gray", "border-right": "1px solid gray"})
   )
   .append( $(TH)
     .css({"position": "sticky", "top": "0", "background-color": "white", "z-index": 1, "border-bottom": "1px solid gray", "border-right": "1px solid gray"})
   ) //for buttons
   .append( $(TH)
     .css({"position": "sticky", "top": "0", "background-color": "white", "z-index": 1, "border-bottom": "1px solid gray", "border-right": "1px solid gray"})
     .append( !has_right(R_SUPER)? $(LABEL) : $(LABEL).addClass("ui-icon").addClass("ui-icon-plusthick").addClass("ui-button")
       .css({"color": color_table_buttons})
       .click(function() {
         $(".range_btn").show();
         let table_div=$("#vlans_list").find(".table_div");
         vlan_range_dialog(undefined, function() {
           let scroll=table_div.scrollTop();

           table_div.data("scroll", scroll);
           $("#vlans_list").find("SELECT.domain_sel").trigger("change");
         })
       })
     )
   ) //for ranges
  ;

  let table=$(TABLE).addClass("vlans_table")
   .append( $(THEAD)
     .append( head_tr )
   )
   .appendTo( table_div )
  ;

  let tbody=$(TBODY).addClass("vlans_list")
   .data("opt", opt)
   .data("presel", presel_vlan_id)
   .data("donefunc", donefunc)
   .append( $(TR).append( $(TD).prop("colaspan", 99).text("Выберете домен") ) )
   .appendTo( table )
   .on("sel_change", function() {
     let sel_count=0;
     let _opt=$(this).data("opt");
     $(this).find(".vlan_row").each(function() {
       if($(this).find("INPUT.select_checkbox").is(":checked")) sel_count++;
     });
     let disable= sel_count == 0 && _opt['return'] == "many";
     $(this).closest(".dialog_start").dialog("widget").find("BUTTON.confirm_btn").prop("disabled", disable).css({"color": disable?"gray":"black"});
   })
  ;

  let query={"action": "get_vdomains"};
  if(presel_vlan_id != undefined) {
    if(typeof(presel_vlan_id) === 'object') {
      if(presel_vlan_id.length > 0) {
        query['focus_on_vlan_id']=presel_vlan_id[0];
      };
    } else {
      query['focus_on_vlan_id']=presel_vlan_id;
    };
    
  };

  run_query(query, function(ret_data) {
    watch(TICK_vd, 0);
    ret_data['ok']['vds'].sort(function(a, b) {
      return String(a['vd_name']).localeCompare(String(b['vd_name']));
    });
    for(let i=0; i < ret_data['ok']['vds'].length; i++) {
      domain_sel.append( vdomain_row(ret_data['ok']['vds'][i]) );
    };
    if(presel_vlan_id != undefined && ret_data['ok']['select_vd_id'] != undefined) {
      domain_sel.val(ret_data['ok']['select_vd_id']).trigger("change");
    } else if(ret_data['ok']['vds'].length == 1) {
      domain_sel.val(ret_data['ok']['vds'][0]['vd_id']).trigger("change");
    };
  });

  dialog.dialog(d);
};

function user_edit(user_id, opt, donefunc) {
  if(opt == undefined) { error_at(); return; };
  if(user_id == undefined) { error_at(); return; };;

  if( $("#user_edit"+user_id).length != 0) { return; };

  let dialog=$(DIV).myid("user_edit"+user_id)
   .data("opt", opt)
   .data("id", user_id)
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
    minWidth:800,
    minHeight:500,
    //width: "auto",
    buttons: [],
    close: function() {
      let _id=$(this).data("id");
      if(_id != undefined) {
        unwatch(TICK_user, _id);
        unwatch(TICK_group, 0);
      };
      $(this).dialog("destroy");
      $(this).remove();
    },
  };

  if(has_right(R_SUPER)) {
    d['buttons'].push({ "text": "Сохранить", "class": "confirm_btn", "click": function() {
      let _dialog=$(this);
      let _id=$(this).data("id");
      if(_id == undefined) { error_at(); return; };

      let query={"action": "save_user", "user_id": _id};

      let new_state=$(this).find("input.state_radio:checked").val();
      if(new_state == undefined || !String(new_state).match(/^(?:-[12]|[01])$/)) { error_at(); return; };

      if(_id != ud['user']['user_id']) {
        query['user_state'] = new_state;
      };

      let groups=Array();

      $(this).find(".groups_list").find(".groups_list_row").each(function() {
        let group=$(this).data("data");
        if(group == undefined || group['group_id'] == undefined) { error_at(); return false; };
        groups.push( group['group_id'] );
      });

      if(groups.length == 0) {
        $(this).find(".ui-icon-plusthick").animateHighlight();
        return;
      };

      let prev_groups=Array();
      
      let prev_list=$(this).find(".groups_list").data("redo_data");

      for(let i=0; i < prev_list.length; i++) {
        let group_id=prev_list[i]['group_id'];
        prev_groups.push(group_id);
      };

      groups.sort(function(a,b) { return a-b; });
      prev_groups.sort(function(a,b) { return a-b; });

      if(groups.join(",") == prev_groups.join(",") &&
         (_id == ud['user']['user_id'] || $(this).data("prev_state") == new_state)
      ) {
        _dialog.dialog("close");
        return;
      };

      query['user_groups']=groups;


      run_query(query, function(ret_data) {
        _dialog.dialog("close");
        if(donefunc != undefined) donefunc(ret_data['ok']);
      });
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
               .addClass("state_radio")
               .val(1)
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
               .addClass("state_radio")
               .val(0)
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
               .addClass("state_radio")
               .val(-1)
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
               .addClass("state_radio")
               .val(-2)
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
     .append( (!opt['allow_groups_change'] || !has_right(R_SUPER)) ? $(LABEL) : $(LABEL)
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
     .append( (!opt['allow_groups_change'] || !has_right(R_SUPER)) ? $(LABEL) : $(LABEL)
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
    dialog.data("data", data['ok']);

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
    if(data['ok']['user_last_login'] != 'hidden' && data['ok']['user_last_login'] != 0) {
      table.find(".user_last_login").text(from_unix_time(data['ok']['user_last_login']));
    } else {
      table.find(".user_last_login").text('Скрыто').css({"color": "gray"});
    };

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
      throw("error");
    };

    dialog.data("prev_state", data['ok']['user_state']);

    table.find(".states_list").find("INPUT").checkboxradio("refresh");

    for(let i=0; i < data['ok']['user_groups'].length; i++) {
      data['ok']['user_groups'][i]['_no_user_info_btn'] = true;
      if(has_right(R_SUPER) && opt['allow_groups_change']) {
        data['ok']['user_groups'][i]['_minus'] = true;
      };
    };

    for(let i=0; i < data['ok']['user_groups'].length; i++) {
      let group=data['ok']['user_groups'][i];
      let row=groups_list_row(group);
      row.appendTo( groups_table );
    };
    
    groups_table.data("redo_data", data['ok']['user_groups']);

    watch(TICK_user, user_id);
    watch(TICK_group, 0);
  });

  dialog.dialog(d);
};

function users_list_row(user) {
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
             ret_data['_show_info_btn'] = _data['_show_info_btn'];
             row.replaceWith( users_list_row(ret_data) );
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
  if(opt == undefined) { error_at(); return; };
  if(!has_right(R_VIEWANY)) { error_at(); return; };

  if( $("#users_list").length != 0) { error_at(); return; };

  let dialog=$(DIV).myid("users_list")
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
      unwatch(TICK_user, 0);
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

      if(opt['show_sel'] != undefined) {
        user['_sel'] = opt['show_sel'];
      };

      user['_show_info_btn'] = (opt['allow_user_info_btn']);
      user['_allow_groups_change'] = (opt['allow_user_group_change']);

      let row=users_list_row(user);
      row.appendTo( table );
    };

    watch(TICK_user, 0);
  });
};

function group_edit(group_id, opt, donefunc) {
  if(opt == undefined) { error_at(); return; };
  if(group_id == undefined && !has_right(R_SUPER)) { error_at(); return; };

  let id="group_edit";
  if(group_id != undefined) { id += group_id; };

  if( $("#"+id).length != 0) { return; };

  let allow_group_edit = opt['allow_edit'];

  let dialog=$(DIV).myid(id)
   .data("opt", opt)
   .data("id", group_id)
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
      let _id=$(this).data("id");
      if(_id != undefined) {
        unwatch(TICK_group, _id);
      };
      unwatch(TICK_user, 0);
      $(this).dialog("destroy");
      $(this).remove();
    },
  };

  if(group_id == undefined || (has_right(R_SUPER) && allow_group_edit)) {
    d['buttons'].push({ "text": (group_id == undefined)?"Создать":"Сохранить", "class": "confirm_btn", "click": function() {
      let _dialog=$(this);

      let group_name=$(this).find(".group_name").val().trim();
      if(! group_name.match(/\S+/)) { $(this).find(".group_name").animateHighlight(); return; };

      let query={"group_name": group_name};

      let group_users=Array();

      $(this).find(".users_list").find(".user_list_row").each(function() {
        let user=$(this).data("data");
        if(user == undefined || user['user_id'] == undefined) { throw("Error"); };
        group_users.push(user['user_id']);
      });

      query['group_users']=group_users;

      let rights=Array();
      let rights_table=$(this).find(".group_rights");

      for(let i=0; i < group_rights.length; i++) {
        let r_elm=rights_table.find(".right_"+group_rights[i]['right']);
        if(r_elm.length != 1) { error_at(); return; };
        if(r_elm.hasClass("on")) push_once(rights, r_elm.data("right"));
      };

      query['group_rights']=rights.join(',');

      let _id=$(this).data("id");

      if(_id == undefined) {
        query['action'] = 'add_group';
      } else {
        query['action'] = 'save_group';
        query['group_id'] = _id;
      };

      run_query(query, function(ret_data) {
        _dialog.dialog( "close" ); 
        if(donefunc != undefined) donefunc(ret_data['ok']);
      });
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
               ret_data[i]['_show_info_btn'] = _opt['allow_user_info_btn'];
               _cont.append( users_list_row( ret_data[i] ) );
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
             _cont.append( users_list_row( _initial_list[i] ) );
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

        data['ok']['group_users'][i]['_show_info_btn'] = opt['allow_user_info_btn'];
      };

      for(let i=0; i < data['ok']['group_users'].length; i++) {
        let user=data['ok']['group_users'][i];
        let row=users_list_row(user);
        users_div.append( row );
      };

      users_div
       .data("redo_data", data['ok']['group_users'])
       .trigger("list_change")
      ;
      watch(TICK_group, group_id);
      watch(TICK_user, 0);
    });
  } else {
    run_query({"action": "get_users"}, function() {
      watch(TICK_user, 0);
    });
  };

  dialog.dialog(d);
};

function groups_list_row(group, donefunc) {
  let ret=$(TR).addClass("groups_list_row")
   .data("data", group)
   .data("donefunc", donefunc)
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
         let table=row.closest("TABLE");
         let prev_data=row.data("data");
         let _donefunc=row.data("donefunc");
         group_edit(prev_data['group_id'], { "allow_edit": prev_data['_allow_edit'], "allow_user_info_btn": !prev_data['_no_user_info_btn'] }, function(ret_data) {
           //copy '_xxx' keys from prev_data
           for(let key in prev_data) {
             if(key.indexOf('_') === 0) {
               ret_data[key] = prev_data[key];
             };
           };
           row.replaceWith( groups_list_row(ret_data, _donefunc) );
           table.trigger("list_change");
         });
       })
     )
   )
  ;

  if(has_right(R_SUPER) && group['_allow_delete']) {
    ret
     .append( $(TD)
       .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-trash").addClass("ui-button")
         .title("Удаление группы")
         .css({"padding-left": "0.2em", "padding-right": "0.2em", "margin-left": "0.5em", "color": "coral"})
         .click(function() {
           let row=$(this).closest(".groups_list_row");
           let table=row.closest("TABLE");
           let prev_data=row.data("data");
           show_confirm_checkbox("Подтвердите удаление группы "+prev_data['group_name']
             +".\nВНИМАНИЕ! Группа и все связаные с нею права доступа\nбудут удалены сразу и без возможности восстановления!",
           function() {
             run_query({"action": "delete_group", "group_id": prev_data['group_id']}, function() {
               row.remove();
               table.trigger("list_change");
             });
           });
         })
       )
     )
    ;
  };

  return ret;
};

function groups_list(select_gr_ids, exclude_list, opt, donefunc) {
  if(opt == undefined) { error_at(); return; };
  if( $("#groups_list").length != 0) { error_at(); return; };

  let presel_list;
  if(typeof(select_gr_ids) == "object") {
    presel_list = select_gr_ids;
  } else {
    presel_list = [select_gr_ids];
  };

  let dialog=$(DIV).myid("groups_list")
   .data("opt", opt)
   .data("donefunc", donefunc)
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
      unwatch(TICK_group, 0);
      $(this).dialog("destroy");
      $(this).remove();
    },
    open: function() {
      if(opt['return'] == "many" && donefunc != undefined && presel_list.length == 0) {
        $(this).dialog("widget").find("BUTTON.confirm_btn").prop("disabled", true).css({"color": "gray"});
      };
    }
  };

  if((opt['return'] == "any" || opt['return'] == "many") && donefunc != undefined) {
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

  if(opt['return'] == "many" && donefunc != undefined) {
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

  if(has_right(R_SUPER) && opt['allow_add']) {
    table
     .append( $(THEAD)
       .append( $(TR)
         .append( $(TD)
           .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-plusthick").addClass("ui-button")
             .title("Создать группу")
             .css({"color": "green"})
             .click(function() {
               let _opt=$(this).closest(".dialog_start").data("opt");
               let _donefunc=$(this).closest(".dialog_start").data("donefunc");
               let _table=$(this).closest(".dialog_start").find("TABLE");
               let _allow_edit=true;
               let _allow_user_info_btn = _opt['allow_user_info_btn'] === true;
               group_edit(undefined, { "allow_edit": _allow_edit, "allow_user_info_btn": _allow_user_info_btn}, function(ret_data) {
                 if(_opt['return'] == "one") {
                   ret_data['_sel'] = "one";
                 } else if(_opt['return'] != undefined) {
                   ret_data['_sel'] = "multi";
                 };       

                 ret_data['_no_user_info_btn'] = (_opt['allow_user_info_btn'] === false);
                 ret_data['_allow_edit'] = _opt['allow_edit'];
                 ret_data['_allow_delete'] = _opt['allow_delete'];

                 table.find("TBODY").append( groups_list_row(ret_data, _donefunc) );
                 table.trigger("list_change");
               })
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
    let groups=data['ok'];
    for(let i=0; i < groups.length; i++) {
      let check=in_array(presel_list, groups[i]['group_id']);
      groups[i]['_presel'] = check;
    };

    groups.sort(function(a, b) {
      if(a['_presel'] != b['_presel']) {
        if(a['_presel']) { return -1; } else { return 1; };
      } else {
        return String(a['group_name']).localeCompare(String(b['group_name']));
      };
    });

    for(let i=0; i < groups.length; i++) {
      let group=groups[i];
      if(in_array(exclude_list, group['group_id'])) continue;

      if(opt['return'] == "one") {
        group['_sel'] = "one";
      } else if(opt['return'] != undefined) {
        group['_sel'] = "multi";
      };

      group['_no_user_info_btn'] = (opt['allow_user_info_btn'] === false);
      group['_allow_edit'] = opt['allow_edit'];
      group['_allow_delete'] = opt['allow_delete'];

      let row=groups_list_row(group, donefunc);
      row.appendTo( tbody );
    };
    watch(TICK_group, 0);
  });
};

function group_net_right_div(rights_set, gr, mask, opt) {
  if(opt == undefined) { error_at(); return; };
  let ret=$(DIV)
   .css({"white-space": "pre", "margin-bottom": "0.2em"})
   .addClass("group_rights_div")
  ;

  if(_debug_opts) {
    ret.append( $(LABEL).addClass("ui-icon").addClass("ui-icon-info").css({"color": "lightgray", "font-size": "xx-small"}).title(jstr(gr)+"\n"+jstr(mask)+"\n"+jstr(opt)) );
  };

  if(gr == undefined) {
    ret.css({"background-color": "yellow"});
  };

  let rigths_span=$(SPAN);

  for(let i=0; i < rights_set.length; i++) {
    if(((rights_set[i]['right'] & mask) >>> 0) > 0) {
      let is_set = (gr != undefined && ((Number(gr['rmask']) & rights_set[i]['right']) >>> 0) > 0);
      if(is_set || opt['allow_edit'] == true) {
        let r_label=$(LABEL).addClass("right")
         .toggle(is_set || gr == undefined)
         .css({"border": "1px solid gray", "padding-left": "0.1em", "padding-right": "0.1em", "margin-left": "0.3em"})
         .text(rights_set[i]['label_text'])
         .title(rights_set[i]['label_descr'])
         .data("right", rights_set[i]['right'])
         .data("val", is_set?rights_set[i]['right']:0)
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

  if(opt['allow_edit'] == true) {
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
  if(opt['allow_edit'] == true) {
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

  let dialog=$(DIV).myid("v4_global_range_dialog")
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
      let _id=$(this).data("id");
      if(_id != undefined) unwatch(TICK_v4r, _id);
      unwatch(TICK_group, 0);
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
            if(in_array(groups, gr_id)) { throw("Error"); };
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
       .append( $(INPUT).myid("v4range_start").prop({"placeholder": "x.x.x.x", "readonly": !has_right(R_SUPER)})
         .on("change input", validate_v4range)
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Окончание:") )
     )
     .append( $(TD)
       .append( $(INPUT).myid("v4range_stop").prop({"placeholder": "x.x.x.x", "readonly": !has_right(R_SUPER)})
         .on("change input", validate_v4range)
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Наименование:") )
     )
     .append( $(TD)
       .append( $(INPUT).myid("v4range_name").prop({"placeholder": "Краткое наименование", "readonly": !has_right(R_SUPER)})
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Описание:") )
     )
     .append( $(TD)
       .append( $(TEXTAREA).myid("v4range_descr").prop({"readonly": !has_right(R_SUPER)})
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Скрытый:") )
     )
     .append( $(TD)
       .append( $(INPUT).myid("v4range_invisible").prop({"type": "checkbox"})
         .click(function() { return has_right(R_SUPER); })
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Стиль линии/текста (JSON):") )
     )
     .append( $(TD)
       .append( $(INPUT).myid("v4range_style").prop({"placeholder": "{\"color\": \"red\"}", "readonly": !has_right(R_SUPER)})
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
       .append( $(INPUT).myid("v4range_icon").prop({"placeholder": "ui-icon-info", "readonly": !has_right(R_SUPER)})
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Стиль значка (JSON):") )
     )
     .append( $(TD)
       .append( $(INPUT).myid("v4range_icon_style").prop({"placeholder": "{\"color\": \"red\"}", "readonly": !has_right(R_SUPER)})
         .on("change input", function() { validate_json_elm.call(this, "lightgreen", "red"); })
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Права доступа:") )
     )
     .append( $(TD)
       .append( $(DIV).myid("v4range_rights") 
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
               $("DIV#v4range_rights").append( group_net_right_div(group_net_rights, undefined, (NR_VIEWNAME | NR_VIEWOTHER | RR_TAKE_NET) >>> 0, {"allow_edit": true, "allow_delete": true}) );
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
        $("DIV#v4range_rights").append( group_net_right_div(group_net_rights, data['ok']['range_group_rights'][i], (NR_VIEWNAME | NR_VIEWOTHER | RR_TAKE_NET) >>> 0, { "allow_edit": has_right(R_SUPER), "allow_delete": has_right(R_SUPER)}) );
      };

      watch(TICK_v4r, v4r_id);
      watch(TICK_group, 0);
    });
  } else {
    run_query({"action": "get_groups"}, function() {
      watch(TICK_group, 0);
    });
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

    let style;
    let icon_style;

    try {
      style=JSON.parse(ranges[r]['v4r_style']);
    } catch(err) {
      style={};
    };

    try {
      icon_style=JSON.parse(ranges[r]['v4r_icon_style']);
    } catch(err) {
      icon_style={};
    };

    let icon=range_icon(ranges[r]['v4r_icon'])
     .css( icon_style )
     .css(s_ranges_spacing)
     .title( ranges[r]['v4r_descr'] )
    ;

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
         .css( style )
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
          if(has_right(R_VIEWANY) || (data['nets'][row_net]['rmask_effective'] & NR_VIEWOTHER) > 0) {
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

    let net_name_css={"padding-left": "0.5em", "padding-right": "0.5em", "border-left": "1px solid gray"};
    if(row_has_nets) {
      net_name_css['background-color'] = color_taken;
      net_name_css['border-bottom'] = "1px solid gray";
      net_name_css['border-top'] = "1px solid gray";
    } else {
      net_name_css['background-color'] = "white";
    };

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

        let style;
        try {
          style=JSON.parse(range['v4r_style']);
        } catch(err) {
          style={};
        };

        r_elm
         .title(ranges2lang(true, "ru", 1)+": "+v4long2ip(range['v4r_start'])+" - "+v4long2ip(range['v4r_stop'])+"\n"+range['v4r_name']+"\nНажмите для более подробной информации")
         .css( style )
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

    tr.addClass("bg_colored");
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

  unwatch();

  run_query({"action": "v4get_net", "net": $R['net'], "mask": $R['masklen']}, function(data) {
    if(data['ok']['type'] == "nav") {
      watch(TICK_v4net, 0);
      watch(TICK_v4r, 0);
      v4nav(data['ok']);
    } else {
      watch(TICK_v4net, data['ok']['net']['v4net_id']);
      //watch(TICK_v4net, 0);
      //watch(TICK_v4r, 0);
      v4view(data['ok']);
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
         .append( $(INPUT).myid("v4goto_net").prop({"placeholder": "x.x.x.x/mm", "type": "search"})
           .title("Введите адрес сети в CIDR нотации. Если сеть не существует, интерфейс перейдет в режим навигации ближайшей в сторону увеличения сети, либо к просмотру/редактированию существующей сети")
           .enterKey(function() { $("#v4goto_net_btn").trigger("click"); })
         )
       )
       .append( $(TD)
         .append( $(BUTTON).button({"icon": "ui-icon-sitemap"}).myid("v4goto_net_btn")
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

function get_columns_list_row(ic) {
  let ret=$(DIV).addClass("column")
   .data("id", ic['ic_id'])
   .css({"margin": "5px", "white-space": "pre", "background-color": "white", "border": "1px solid gray", "padding": "5px"})
  ;

  if(has_right(R_SUPER)) {
    ret
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-arrow-2-n-s").addClass("handle")
       .css({"margin-right": "0.5em"})
       .title("Переместите вверх-вниз для изменения порядка сортировки.\nПорядок сортировки ОБЩИЙ для всех шаблонов и сетей!")
     )
    ;
  };

  if(ic['checked'] != undefined) {
    ret
     .append( $(INPUT).addClass("select_checkbox")
       .prop({"type": "checkbox", "checked": Number(ic['checked']) > 0})
       .data("readonly", !has_right(R_SUPER))
       .click(function() {
         return !$(this).data("readonly");
       })
       .on("change", function() {
         if(!TEMPLATES_AUTOSAVE) {
           $(this).addClass("unsaved");
           $("#templates_autosave_label").css({"background-color": "yellow"});
           return;
         };
         let _templates_list=$(this).closest(".root_pane").find(".templates_list");
         if(_templates_list.length != 1) { error_at(); return; };
         let _tp_id=_templates_list.data("id");
         if(_tp_id == undefined) { error_at(); return; };
         let _ic_id = $(this).closest(".column").data("id");
         if(_ic_id == undefined) { error_at(); return; };

         let query={"tp_id": _tp_id, "ic_id": _ic_id};
         if($(this).is(":checked")) {
           query['action'] = "add_template_column";
         } else {
           query['action'] = "delete_template_column";
         };

         let _this=$(this);
         run_query(query, function() {
           _this.removeClass("unsaved");
         });
       })
     )
    ;
  };

  ret
   .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-bullets").addClass("ui-button")
     .css({"color": color_table_buttons})
     .click(function(e) {
       e.stopPropagation();
       let row=$(this).closest(".column");
       let selected=row.find("INPUT.select_checkbox").is(":checked");
       let id=row.data("id");
       edit_column(id, !has_right(R_SUPER)?undefined:function(data) {
         if(row.find("INPUT.select_checkbox").length == 1) {
           data['checked'] = selected?1:0;
         };
         let new_row=get_columns_list_row(data);
         row.replaceWith(new_row);
       })
     })
   )
  ;
  if(has_right(R_SUPER)) {
    ret
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-trash").addClass("ui-button")
       .css({"color": ic['uses'] == 0?"coral":"gray", "margin-left": "0.5em"})
       .title(ic['uses'] == 0?"Удалить поле":"Удаление невозможно, так как поле используется в "+ic['uses']+" сетях")
       .click(ic['uses'] > 0? function(e) {e.stopPropagation();} : function(e) {
         e.stopPropagation();
         let row=$(this).closest(".column");
         let list=row.parent();
         let _id=row.data("id");
         show_confirm_checkbox("Подтвердите удаление поля.", function() {
           run_query({"action": "delete_column", "ic_id": _id}, function() {
             row.remove();
             list.trigger("sel_change");
           });
         });
       })
     )
    ;
  };

  ret
   .append( $(LABEL)
     .css({"margin-left": "0.5em"})
     .text(ic['ic_name'])
     .title(ic['ic_descr'])
   )
  ;

  return ret;
};

function edit_column(ic_id, donefunc) {
  if(ic_id == undefined && donefunc == undefined) { error_at(); return; };
  if(ic_id == undefined && !has_right(R_SUPER)) { error_at(); return; };

  if( $("#column_edit").length != 0) { error_at(); return; };

  let title="Просмотр поля IP";
  if(ic_id == undefined) {
    title="Создание поля IP";
  } else if(donefunc != undefined) {
    title="Изменение поля IP";
  };

  let dialog=$(DIV).myid("column_edit")
   .data("id", ic_id)
   .data("donefunc", donefunc)
   .addClass("dialog_start")
   .prop("title", title)
   .css({"white-space": "pre", "font-size": "larger"})
   .appendTo("BODY")
  ;

  let d={
    modal:true,
    maxHeight: 1000,
    minHeight: 600,
    minWidth:800,
    buttons: [],
    close: function() {
      let _id=$(this).data("id");
      if( _id != undefined ) unwatch(TICK_ic, _id);
      $(this).dialog("destroy");
      $(this).remove();
    },
    open: function() {
      $(this).dialog("widget").find(".ui-dialog-buttonset").css({"width": "100%", "text-align": "right"});
    }
  };

  if(donefunc != undefined) {
    d['buttons'].push({
      "text": (ic_id == undefined?"Создать":"Сохранить"),
      "click": function() {
        let _dialog=$(this);
        let _donefunc=$(this).data("donefunc");
        let name_input=$(this).find("INPUT.ic_name");
        let ic_name=name_input.val();

        if(!ic_name.match(/\S/)) {
          name_input.animateHighlight();
          return;
        };
        let ic_descr=$(this).find("TEXTAREA.ic_descr").val();
        if(ic_descr == undefined) { error_at(); return; };

        let query={"ic_name": ic_name, "ic_descr": ic_descr};

        let ic_default=$(this).find("INPUT.ic_default").is(":checked")?1:0;
        query['ic_default']=ic_default;

        let ic_style_input=$(this).find(".ic_style");
        if(ic_style_input.length != 1) { throw("error"); };
        let ic_style=ic_style_input.val();
        try {
          JSON.parse(ic_style);
          query['ic_style']=ic_style;
        } catch(err) {
          ic_style_input.animateHighlight();
          return;  
        };

        let ic_icon_style_input=$(this).find(".ic_icon_style");
        if(ic_icon_style_input.length != 1) { throw("error"); };
        let ic_icon_style=ic_icon_style_input.val();
        try {
          JSON.parse(ic_icon_style);
          query['ic_icon_style']=ic_icon_style;
        } catch(err) {
          ic_icon_style_input.animateHighlight();
          return;  
        };

        let ic_regexp_input=$(this).find(".ic_regexp");
        if(ic_regexp_input.length != 1) { throw("error"); };
        let ic_regexp=ic_regexp_input.val();
        try {
          new RegExp(ic_regexp);
          query['ic_regexp']=ic_regexp;
        } catch(err) {
          ic_regexp_input.animateHighlight();
          return;  
        };

        let ic_icon_input=$(this).find(".ic_icon");
        if(ic_icon_input.length != 1) { throw("error"); };
        let ic_icon=ic_icon_input.val();
        query['ic_icon']=ic_icon;

        let _id=$(this).data("id");
        if(_id == undefined) {
          query['action'] = "add_column";
        } else {
          query['action'] = "edit_column";
          query['ic_id'] = _id;
        };
        run_query(query, function(data) {
          _dialog.dialog("close");
          if(_donefunc != undefined) {
            _donefunc(data['ok']);
          };
        });
      }
    });
  };

  d['buttons'].push({ "text": (donefunc != undefined)?"Отмена":"Закрыть", "click": function() {$(this).dialog( "close" ); } });

  let readonly= donefunc == undefined;

  dialog
   .append( $(TABLE)
     .append( $(TR)
       .append( $(TD).css("text-align", "right")
         .text( "Наименование:" )
       )
       .append( $(TD)
         .append( $(INPUT).addClass("ic_name")
           .css({"width": "25em"})
           .prop("readonly", readonly)
         )
       )
     )
     .append( $(TR)
       .append( $(TD).css("text-align", "right")
         .text( "По умолчанию:" )
         .dotted( "Назначать по умолчанию на вновь создаваемые шаблоны.\nНе влияет на уже созданные!" )
       )
       .append( $(TD)
         .append( $(INPUT).addClass("ic_default")
           .prop("type", "checkbox")
           .data("readonly", readonly)
           .click(function() { return !$(this).data("readonly"); })
         )
       )
     )
     .append( $(TR)
       .append( $(TD).css("text-align", "right")
         .text( "Regexp:" )
         .dotted( "Регулярное выражение, с помощью которого проверять ввод пользователя." )
       )
       .append( $(TD)
         .append( $(INPUT).addClass("ic_regexp")
           .css({"width": "25em"})
           .prop("readonly", readonly)
           .on("input", function() {
             let example=$(this).closest(".dialog_start").find("INPUT.ic_style_example");
             try {
               let r=new RegExp( $(this).val() );
               $(this).css({"background-color": "lightgreen"});
               if(r.test( example.val() )) {
                 example.css({"background-color": "lightgreen"});
               } else {
                 example.css({"background-color": "coral"});
               };
             } catch(err) {
               $(this).css({"background-color": "coral"});
               example.css({"background-color": "gray"});
             };
           })
         )
       )
     )
     .append( $(TR)
       .append( $(TD).css("text-align", "right").css({"vertical-align": "top"})
         .text( "Стиль (JSON):" )
         .dotted( "Стиль отображения поля, применяется к INPUT или LABEL элемента ввода/отображения значения поля.\nДолжен содержать JSON объект, которы будет передан в функцию jQuery.css()" )
       )
       .append( $(TD).css({"vertical-align": "top"})
         .append( $(INPUT).addClass("ic_style")
           .val("{}")
           .css({"width": "25em"})
           .prop("readonly", readonly)
           .prop("placeholder", "{\"width\": \"10em\"}")
           .on("input", function() {
             let v;
             try {
               v=JSON.parse( $(this).val() );
               $(this).parent().find(".ic_style_example").css(v);
               $(this).css({"background-color": "lightgreen"});
             } catch(err) {
               $(this).css({"background-color": "coral"});
             };
           })
         )
         .append( $(BR) )
         .append( $(INPUT).addClass("ic_style_example").val("Пример INPUT")
           .on("input", function() {
             try {
               let r=new RegExp( $(this).closest(".dialog_start").find(".ic_regexp").val() );
               if(r.test( $(this).val() )) {
                 $(this).css({"background-color": "lightgreen"});
               } else {
                 $(this).css({"background-color": "coral"});
               };
             } catch(err) {
               $(this).css({"background-color": "gray"});
             };
           })
         )
         .append( $(BR) )
         .append( $(LABEL).addClass("ic_style_example").text("Пример LABEL").css({"display": "inline-block", "border": "1px solid gray", "margin-top": "0.2em"}) )
       )
     )
     .append( $(TR)
       .append( $(TD).css("text-align", "right").css({"vertical-align": "top"})
         .text( "Значек:" )
         .dotted( "ui-icon-xxx - Класс jQuery UI icon\n&#NNNN; - HTML Unicode символ\nURL - Ссылка на .png, .jpg, .jpeg, .ico, .gif" )
       )
       .append( $(TD)
         .append( $(INPUT).addClass("ic_icon").prop("placeholder", "ui-icon-blank")
           .css({"width": "25em"})
           .on("input", function() {
             let new_icon;

             if($(this).val().length > 5) {
               new_icon=any_icon($(this).val()).addClass("ic_icon_example");
             } else {
               new_icon=$(LABEL).addClass("ui-icon").addClass("ui-icon-blank").addClass("ic_icon_example");
             };

             let style;
             try {
               style=JSON.parse($(this).closest(".dialog_start").find(".ic_icon_style").val());
             } catch(err) {
               style={};
             };

             if(!new_icon.hasClass("wrong")) {
               new_icon.css(style);
               $(this).css({"background-color": "lightgreen"});
             } else {
               $(this).css({"background-color": "coral"});
             };

             $(this).parent().find(".ic_icon_example").replaceWith(new_icon);
           })
         )
         .append( $(BR) )
         .append( $(LABEL).text("Пример: ") )
         .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-blank").addClass("ic_icon_example") )
       )
     )
     .append( $(TR)
       .append( $(TD).css("text-align", "right")
         .text( "Стиль зачка (JSON):" )
         .dotted( "Стиль отображения значка, применяется к IMG или LABEL элемента отображения значка.\nДолжен содержать JSON объект, которы будет передан в функцию jQuery.css()" )
       )
       .append( $(TD)
         .append( $(INPUT).addClass("ic_icon_style")
           .val("{}")
           .css({"width": "25em"})
           .prop("readonly", readonly)
           .prop("placeholder", "{\"color\": \"green\"}")
           .on("input", function() {
             let v;
             try {
               v=JSON.parse( $(this).val() );
               let icon_example=$(this).closest(".dialog_start").find(".ic_icon_example");
               if(!icon_example.hasClass("wrong")) {
                 icon_example.css(v);
               };
               $(this).css({"background-color": "lightgreen"});
             } catch(err) {
               $(this).css({"background-color": "coral"});
             };
           })
         )
       )
     )
     .append( $(TR)
       .append( $(TD).css({"text-align": "right", "vertical-align": "top"})
         .text( "Коментарий:" )
       )
       .append( $(TD)
         .append( $(TEXTAREA).addClass("ic_descr")
           .css({"width": "25em"})
           .prop("readonly", readonly)
         )
       )
     )
   )
  ;

  if(ic_id != undefined) {
    run_query({"action": "get_column", "ic_id": ic_id}, function(data) {
      dialog.find(".ic_name").val(data['ok']['ic_name']);
      dialog.find(".ic_descr").val(data['ok']['ic_descr']);
      dialog.find(".ic_default").prop("checked", Number(data['ok']['ic_default']) > 0);
      dialog.find(".ic_regexp").val(data['ok']['ic_regexp']);
      dialog.find(".ic_style").val(data['ok']['ic_style']);
      dialog.find(".ic_icon").val(data['ok']['ic_icon']);
      dialog.find(".ic_icon_style").val(data['ok']['ic_icon_style']);

      dialog.find(".ic_icon").trigger("input");
      dialog.find(".ic_icon_style").trigger("input");
      dialog.find(".ic_style").trigger("input");
      dialog.find(".ic_regexp").trigger("input");

      watch(TICK_ic, ic_id);
    });
  };

  dialog.dialog(d);
};

function edit_template(tp_id, donefunc) {
  if(tp_id == undefined && donefunc == undefined) { error_at(); return; };
  if(tp_id == undefined && !has_right(R_SUPER)) { error_at(); return; };

  if( $("#template_edit").length != 0) { error_at(); return; };

  let title="Просмотр шаблона";
  if(tp_id == undefined) {
    title="Создание шаблона";
  } else if(donefunc != undefined) {
    title="Изменение шаблона";
  };

  let dialog=$(DIV).myid("template_edit")
   .data("id", tp_id)
   .data("donefunc", donefunc)
   .addClass("dialog_start")
   .prop("title", title)
   .css({"white-space": "pre", "font-size": "larger"})
   .appendTo("BODY")
  ;

  let d={
    modal:true,
    maxHeight: 1000,
    minHeight: 600,
    minWidth:800,
    buttons: [],
    close: function() {
      let _id=$(this).data("id");
      if( _id != undefined ) unwatch(TICK_tp, _id);
      $(this).dialog("destroy");
      $(this).remove();
    },
    open: function() {
      $(this).dialog("widget").find(".ui-dialog-buttonset").css({"width": "100%", "text-align": "right"});
    }
  };

  if(donefunc != undefined) {
    d['buttons'].push({
      "text": (tp_id == undefined?"Создать":"Сохранить"),
      "click": function() {
        let _dialog=$(this);
        let _donefunc=$(this).data("donefunc");
        let name_input=$(this).find("INPUT.tp_name");
        let tp_name=name_input.val();
        if(!tp_name.match(/\S/)) {
          name_input.animateHighlight();
          return;
        };
        let tp_descr=$(this).find("TEXTAREA.tp_descr").val();
        if(tp_descr == undefined) { error_at(); return; };

        let query={"tp_name": tp_name, "tp_descr": tp_descr};
        let _id=$(this).data("id");
        if(_id == undefined) {
          query['action'] = "add_template";
        } else {
          query['action'] = "edit_template";
          query['tp_id'] = _id;
        };
        run_query(query, function(data) {
          _dialog.dialog("close");
          if(_donefunc != undefined) {
            _donefunc(data['ok']);
          };
        });
      }
    });
  };

  d['buttons'].push({ "text": (donefunc != undefined)?"Отмена":"Закрыть", "click": function() {$(this).dialog( "close" ); } });

  let readonly= donefunc == undefined;

  dialog
   .append( $(TABLE)
     .append( $(TR)
       .append( $(TD).css("text-align", "right")
         .text( "Наименование:" )
       )
       .append( $(TD)
         .append( $(INPUT).addClass("tp_name")
           .prop("readonly", readonly)
         )
       )
     )
     .append( $(TR)
       .append( $(TD).css({"text-align": "right", "vertical-align": "top"})
         .text( "Коментарий:" )
       )
       .append( $(TD)
         .append( $(TEXTAREA).addClass("tp_descr")
           .prop("readonly", readonly)
         )
       )
     )
   )
  ;

  if(tp_id != undefined) {
    run_query({"action": "get_template", "tp_id": tp_id}, function(data) {
      dialog.find(".tp_name").val(data['ok']['tp_name']);
      dialog.find(".tp_descr").val(data['ok']['tp_descr']);
      watch(TICK_tp, tp_id);
    });
  };

  dialog.dialog(d);
};

function get_template_list_row(tp) {
  let ret=$(DIV).addClass("template")
   .data("id", tp['tp_id'])
   .css({"margin": "5px", "white-space": "pre", "background-color": "white", "border": "1px solid gray", "padding": "5px"})
   .click(function() {
     let list=$(this).parent();
     list.find(".template").css({"font-weight": "normal", "border-right": "1px solid gray"}).removeClass("selected");
     $(this).addClass("selected").css({"font-weight": "bold", "border-right": "10px solid limegreen"});
     list.trigger("sel_change");
   })
   .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-bullets").addClass("ui-button")
     .css({"color": color_table_buttons})
     .click(function(e) {
       e.stopPropagation();
       let row=$(this).closest(".template");
       let selected=row.hasClass("selected");
       let id=row.data("id");
       edit_template(id, !has_right(R_SUPER)?undefined:function(data) {
         let new_row=get_template_list_row(data);
         if(selected) new_row.addClass("selected");
         row.replaceWith(new_row);
       })
     })
   )
  ;
  if(has_right(R_SUPER)) {
    ret
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-trash").addClass("ui-button")
       .css({"color": "coral", "margin-left": "0.5em"})
       .click(function(e) {
         e.stopPropagation();
         let row=$(this).closest(".template");
         let list=row.parent();
         let selected=row.hasClass("selected");
         let _id=row.data("id");
         show_confirm_checkbox("Подтвердите удаление шаблона.", function() {
           run_query({"action": "delete_template", "tp_id": _id}, function() {
             row.remove();
             list.trigger("sel_change");
           });
         });
       })
     )
    ;
  };

  ret
   .append( $(LABEL)
     .css({"margin-left": "0.5em"})
     .text(tp['tp_name'])
     .title(tp['tp_descr'])
   )
  ;

  return ret;
};

function templates_list(opt) {
  if(opt == undefined) { error_at(); return; };
  if($("#templates_list").length != 0) return;

  if(has_right(R_SUPER)) {
    title = "Управление шаблонами";
  } else {
    title = "Просмотр шаблонов";
  };

  let dialog=$(DIV).myid("templates_list")
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
      unwatch(TICK_tp, 0);
      unwatch(TICK_ic, 0);
      unwatch(TICK_n4c, 0);
      unwatch(TICK_n6c, 0);
      let did=$(this).prop("id");
      $(".vlan_range_btn").hide();
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
    }
  };

  dialog
   .append( $(DIV).css({"position": "absolute", "top": "1em", "left": "1em", "right": "1em"})
     .append( $(DIV).css({"display": "inline-block", "float": "right", "white-space": "pre"})
       .append( $(LABEL).prop("for", "templates_autosave").text("Автосохранение: ")
         .myid("templates_autosave_label")
         .title("Автосохранение данных")
       )
       .append( $(INPUT).myid("templates_autosave").prop({"type": "checkbox", "checked": TEMPLATES_AUTOSAVE})
         .on("change", function() {
           TEMPLATES_AUTOSAVE=$(this).is(":checked");
           if(TEMPLATES_AUTOSAVE) {
             $(".columns_list").trigger("sortstop");
             $(".columns_list").find(".column").find("INPUT.select_checkbox.unsaved").trigger("change");
             $("#templates_autosave_label").css({"background-color": "white"}).title("");
           };
         })
       )
     )
   ) 
  ;

  let root_pane;
  let left_pane;
  let right_pane;
  let bar_width=20;
  dialog
   .append( root_pane=$(DIV).css({"position": "absolute", "top": "3em", "left": "1em", "right": "1em", "bottom": "1em"}).addClass("root_pane")
     .css({"vertical-align": "top"})
     .append( left_pane=$(DIV).css({"display": "inline-block", "position": "absolute", "top": "0px", "left": "0px", "bottom": "0px", "width": "300px"}).addClass("left_pane") )
     .append( $(DIV).css({"display": "inline-block", "position": "absolute", "top": "0px", "left": "300px", "bottom": "0px", "width": bar_width+"px"}).addClass("drag_bar") )
     .append( right_pane=$(DIV).css({"display": "inline-block", "position": "absolute", "top": "0px", "left": (300+bar_width)+"px", "bottom": "0px", "right": "0px" }).addClass("right_pane") )
   )
  ;

  root_pane.find(".drag_bar")
   .css({"background-color": "white", "cursor": "col-resize"})
   .draggable({"axis": "x", "containment": "parent", "zIndex": 10000, "stop": function(e, ui) {
     let x_pos=ui.position.left;
     if(x_pos < 200) x_pos=200;
     
     let _root=$(this).closest(".root_pane");
     _root.find(".left_pane").css("width", x_pos);
     $(this).css("left", x_pos);
     _root.find(".right_pane").css("left", x_pos+$(this).width());
   }})
  ;

  let templ_list_top="1.5em";
  let cols_list_top="1.5em";
  let left_head;
  let right_head;

  root_pane.find(".drag_bar")
   .append( $(DIV)
     .css({"position": "absolute", "top": "0px", "left": "0px", "right": "0px", "height": templ_list_top, "background-color": "white"})
   )
   .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-grip-solid-vertical")
     .css({"position": "absolute", "top": "49%", "left": "0px", "right": "0px", "height": "1em", "cursor": "col-resize"})
   )
  ;

  left_pane
   .append( left_head=$(DIV)
     .css({"position": "absolute", "top": "0px", "left": "0px", "right": "0px", "height": templ_list_top, "background-color": "white"})
     .append( $(LABEL).text("Шаблоны ") )
   )
  ;

  right_pane
   .append( right_head=$(DIV)
     .css({"position": "absolute", "top": "0px", "left": "0px", "right": "0px", "height": cols_list_top, "background-color": "white"})
     .append( $(LABEL).text("Поля ") )
   )
  ;

  if(has_right(R_SUPER)) {
    left_head
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-plusthick").addClass("ui-button")
       .title("Создать шаблон")
       .css({"color": color_table_buttons})
       .click(function() {
         let _list=$(this).closest(".root_pane").find(".templates_list");
         edit_template(undefined, function(ret_data) {
           let new_row=get_template_list_row(ret_data);
           _list.prepend(new_row);
           new_row.trigger("click");
         });
       })
     )
    ;
    right_head
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-plusthick").addClass("ui-button")
       .title("Создать поле")
       .css({"color": color_table_buttons})
       .click(function() {
         let _list=$(this).closest(".root_pane").find(".columns_list");
         edit_column(undefined, function(ret_data) {
           let _templates_list=_list.closest(".root_pane").find(".templates_list");
           if(_templates_list.length != 1) { throw("Error"); };
           if(_templates_list.data("id") != undefined) {
             ret_data['checked'] = 0;
           };
           let new_row=get_columns_list_row(ret_data);
           _list.prepend(new_row);
           _list.trigger("sortstop");
         });
       })
     )
    ;
  };

  let templ_list;
  left_pane
   .append( templ_list=$(DIV).addClass("templates_list")
     .css({"position": "absolute", "top": templ_list_top, "left": "0px", "right": "0px", "bottom": "0px",
           "background-color": "#EEEEEE", "overflow-y": "scroll", "border": "1px solid lightgray"
     })
     .on("sel_change", function() {
       let root=$(this).closest(".root_pane");
       let ic_list=root.find(".columns_list");
       let tp_id=undefined;

       let selected=$(this).find(".template.selected");
       if(selected.length > 1) { throw("Error"); };
       if(selected.length == 1) {
         tp_id=selected.data("id");
       };

       $(this).data("id", tp_id);

       let query={"action": "get_columns"};
       if(tp_id != undefined) {
         query['tp_id'] = tp_id;
       };
       ic_list.empty();
       run_query(query, function(data) {
         for(let i=0; i < data['ok'].length; i++) {
           let row = get_columns_list_row(data['ok'][i]);
           ic_list.append( row );
         };
       });
     })
   )
  ;

  let columns_list;
  right_pane
   .append( columns_list=$(DIV).addClass("columns_list")
     .css({"position": "absolute", "top": cols_list_top, "left": "0px", "right": "0px", "bottom": "0px",
           "background-color": "#EEEEEE", "overflow-y": "scroll", "border": "1px solid lightgray"
     })
   )
  ;

  if(has_right(R_SUPER)) {
    columns_list
     .sortable({"handle": ".handle", "containment": "parent", "axis": "y"})
     .on("sortstop", function() {
       if(!TEMPLATES_AUTOSAVE) {
         $("#templates_autosave_label").css({"background-color": "yellow"});
         return;
       };
       let sort=10;
       let positions={};
       $(this).find(".column").each(function() {
         let _id=$(this).data("id");
         positions[_id] = sort;
         sort += 10;
       });
       run_query({"action": "reorder_columns", "positions": positions});
     })
    ;
  };

  dialog.dialog(d);

  run_query({"action": "get_templates"}, function(data) {
    watch(TICK_tp, 0);
    watch(TICK_ic, 0);
    watch(TICK_n4c, 0);
    watch(TICK_n6c, 0);

    for(let i=0; i < data['ok'].length; i++) {
      let row=get_template_list_row(data['ok'][i]);
      templ_list.append(row);
    };
    templ_list.trigger("sel_change");
  });
};

function add_site_node( ref, site ) {
  let node_id="site_"+site['site_id'];
  let parent_id;

  if(site['site_fk_site_id'] == null) {
    parent_id = "#";
  } else {
    parent_id = "site_"+site['site_fk_site_id'];
  };
  let new_id = ref.create_node(
    parent_id,
    {"id": node_id, "text": site['site_name'] }
  );
  if(new_id != node_id ) { error_at(); return; };

  ref.deselect_all(true);
  ref.select_node( new_id );
  ref.edit( new_id );
};

function sites_list(presel, opt, donefunc) {
  if(opt == undefined) { error_at(); return; };
  if($("#sites_list").length != 0) return;

  let title;

  if(!opt['readonly']) {
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
      unwatch(TICK_site, 0);
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
      let _opt=$(this).data("opt");
      if(_opt["return"] == "many") {
        $(this).dialog("widget").find(".confirm_btn").prop('disabled', true).css({"color": "gray"});
      };
    }
  };

  if(donefunc != undefined && opt['return'] != undefined) {
    d['buttons'].push({
      "text": "Выбрать",
      "class": "confirm_btn",
      "click": function() {
        let _dialog=$(this);
        let _donefunc=$(this).data("donefunc");
        let _opt=$(this).data("opt");

        let selected = _dialog.find(".tree").jstree(true).get_selected();
        if(selected.length == 0 && _opt['return'] == "many") return;
        if(selected.length > 1 && _opt['return'] == "one") { error_at(); return; };

        let ids=[];
        for(let i=0; i < selected.length; i++) {
          let m=String(selected[i]).match(/^site_(\d+)$/);
          if(m === null) { error_at(); return false; };
          ids.push(m[1]);
        };

        _dialog.dialog("close");

        _donefunc(ids);
      }
    });
  };

  d['buttons'].push({ "text": (donefunc != undefined)?"Отмена":"Закрыть", "click": function() {$(this).dialog( "close" ); } });

  let head;

  dialog
   .append( head = $(DIV)
     .css({"padding-bottom": "0.5em"})
   )
  ;

  if(!opt['readonly']) {
    head
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-plusthick").addClass("ui-button")
       .css({"color": color_table_buttons, "margin-right": "0.5em", "padding": "0.1em"})
       .title( "Добавить корневой сайт" )
       .click(function() {
         let ref = $("#tree").jstree(true);
         if(ref === false) { error_at(); return; };

         run_query({"action": "add_site", "site_name": "Переименовать", "parent_id": ""}, function(data) {
           add_site_node( ref, data['ok'] );
         });

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
         if(selected_ids.length > 1) { return; };

         let m=String(selected_ids[0]).match(/^site_(\d+)$/);
         if(m === null) { error_at(); return; };
         run_query({"action": "add_site", "site_name": "Переименовать", "parent_id": m[1]}, function(data) {
           add_site_node( ref, data['ok'] );
         });


       })
     )
    ;
    head
     .append( $(LABEL).addClass("ui-icon").addClass("ui-icon-bullets").addClass("ui-button").addClass("site_selected_btn")
       .css({"color": "lightgray", "margin-right": "0.5em", "padding": "0.1em"})
       .title( "Свойства сайта" )
       .click(function() {
         let ref = $("#tree").jstree(true);
         if(ref === false) { error_at(); return; };
         let selected_ids=ref.get_selected();
         if(selected_ids.length == 0) { return; };
         if(selected_ids.length > 1) { return; };
       })
     )
    ;


    if(donefunc != undefined && (opt['return'] == "any" || opt['return'] == "many")) {
      head.append( $(SPAN).text("Используйте Ctrl+click для множественного выделения или снятия выделения").css({"font-size": "smaller"}) );
    };
  };

  dialog.dialog(d);

  let t={
    "core": {
      "check_callback": true,
      "multiple": opt['return'] == "many" || opt['return'] == "any"
    },
    "conditionalselect": opt['readonly'] == true ? function() { return false; } : function() { return true; },
    "plugins" : [ "wholerow", "contextmenu", "conditionalselect" ]
  };

  t["contextmenu"] = {
    "items": {
      "info" : {
        "label": "Подробная информация",
        "icon": "ui-icon ui-icon-bullets color_table_button",
        "action": function(data) {
          let ref = $.jstree.reference(data.reference);
          let this_node=ref.get_node(data.reference);
          let m=String(this_node.id).match(/^site_(\d+)$/);
          if(m === null) { error_at(); return; };
        }
      },
    },
  };

  if(!opt['readonly']) {
    t["plugins"].push("dnd");
    t["contextmenu"]["items"]["add"] = {
      "label": "Добавить сайт",
      "icon": "ui-icon ui-icon-plus color_table_button",
      "action": function(data) {
        let ref = $.jstree.reference(data.reference);
        let this_node=ref.get_node(data.reference);
        let m=String(this_node.id).match(/^site_(\d+)$/);
        if(m === null) { error_at(); return; };
        run_query({"action": "add_site", "site_name": "Переименовать", "parent_id": m[1]}, function(data) {
          add_site_node( ref, data['ok'] );
        });
      }
    };
    t["contextmenu"]["items"]["del"] = {
      "label": "Удалить сайт",
      "icon": "ui-icon ui-icon-trash color_coral",
      "action": function(data) {
        let ref = $.jstree.reference(data.reference);
        let this_node=ref.get_node(data.reference);
        let m=String(this_node.id).match(/^site_(\d+)$/);
        if(m === null) { error_at(); return; };

        if(this_node.children.length != 0) return;
        show_confirm("Подтвердите удаление сайта.", function() {
          run_query({"action": "delete_site", "safe": 1, "site_id": m[1]}, function(ret_data) {
            if(ret_data['ok'] == "done") {
              ref.delete_node(this_node);
            } else {
              show_confirm_checkbox("Внимание! Сайт задан в свойствах нескольких объектов.\nПодтвердите удаление.", function() {
                run_query({"action": "delete_site", "safe": 0, "site_id": m[1]}, function() {
                  ref.delete_node(this_node);
                });
              });
            };
          });
        });
      }
    };
    t["contextmenu"]["items"]["rename"] = {
      "label": "Переименовать",
      "icon": "ui-icon ui-icon-rename color_table_button",
      "action": function(data) {
        let ref = $.jstree.reference(data.reference);
        let this_node=ref.get_node(data.reference);
        ref.edit(this_node);
      }
    };
  };

  dialog
   .append( tree=$(DIV).myid("tree")
     .css({})
     .jstree(t)
     .on("changed.jstree", function(e, data) {
       let _dialog=$(this).closest(".dialog_start");
       let _opt = _dialog.data("opt");
       if(data.selected.length > 0) {
         $(this).closest(".dialog_start").find(".site_selected_btn").css({"color": color_table_buttons});
         $(this).closest(".dialog_start").dialog("widget").find(".confirm_btn").prop('disabled', false).css({"color": "black"});
       } else {
         $(this).closest(".dialog_start").find(".site_selected_btn").css({"color": "lightgray"});
         if( _opt['return'] == "many" ) {
           $(this).closest(".dialog_start").dialog("widget").find(".confirm_btn").prop('disabled', true).css({"color": "lightgray"});
         };
       };
     })
   )
  ;

  run_query({"action": "get_sites"}, function(data) {
    watch(TICK_site, 0);
    let ref=tree.jstree(true);
    if(data['ok'].length > 0) {
      while(true) {
        let added=false;
        let has_not_added=false;
        for(let i=0; i < data['ok'].length; i++) {
          if(data['ok'][i]['_added'] == undefined) {
            let node_id="site_"+data['ok'][i]['site_id'];
            let parent_id;
            if(data['ok'][i]['site_fk_site_id'] == null) {
              parent_id = "#";
            } else {
              parent_id = "site_"+data['ok'][i]['site_fk_site_id'];
            };

            let parent_node=ref.get_node(parent_id);
            if(parent_node !== false) {
              let new_node_id=ref.create_node(
                parent_node,
                { "id": node_id, "text": data['ok'][i]['site_name'] } );
              if(new_node_id != node_id) {
                error_at();
                return;
              };
              data['ok'][i]['_added'] = true;
              added=true;
            } else {
              has_not_added=true;
            };
          };
        };
        if(!added && has_not_added) {
          error_at();
          return;
        };
        if(!has_not_added) {
          break;
        };
      };
      if(presel != undefined) {
        if(typeof(presel) === "") { presel=[presel]; };
        for(let p=0; p < presel.length; p++) {
          let presel_id=presel[p];
          let node=ref.get_node("site_"+presel_id);
          if(node !== false) {
            ref.select_node(node);
            while(node['parents'].length > 0) {
              node=ref.get_node(node['parents'][0]);
              if(node === false) { error_at(); return; };
              ref.open_node(node, undefined, false);
            };
            let j_node=ref.get_node("site_"+presel_id, true);
            j_node.get(0).scrollIntoView();
          };
        };
      };
    };

    tree
     .on("move_node.jstree", function(e, data) {
       let m=String(data.node.id).match(/^site_(\d+)$/);
       if(m === null) { error_at(); return false; };
       let site_id=m[1];

       let parent_id;
       if(data.parent == "#") {
         parent_id="";
       } else {
         m=String(data.parent).match(/^site_(\d+)$/);
         if(m === null) { error_at("Wrong parent id: "+data.parent); return false; };
         parent_id=m[1];
       };

       let node_id=data.node.id;
       let prev_parent=data.old_parent;
       let prev_pos=data.old_position;
       let ref=$(this).jstree(true);

       run_query({"action": "move_site", "site_id": site_id, "parent_id": parent_id},
         function() {
           ref.open_node(data.parent, undefined, false);
           ref.deselect_node(node_id);
         },
         undefined,
         function(e) {
           ref.move_node(node_id, prev_parent, prev_pos, undefined, undefined, undefined, undefined, true);
           error_dialog("AJAX request error\n"+(e.responseText !== undefined? e.responseText:(e['error'] != undefined?e['error']:"")));
         }
       );

     })
     .on("rename_node.jstree", function(e, data) {
       let m=String(data.node.id).match(/^site_(\d+)$/);
       if(m === null) { error_at(); return false; };

       let ref=$(this).jstree(true);
       let node_id=data.node.id;
       let old_name=data.old;
       run_query({"action": "rename_site", "site_id": m[1], "site_name": data.text}, function() {}, undefined, function(e) {
         ref.rename_node(node_id, old_name, true);
         error_dialog("AJAX request error\n"+(e.responseText !== undefined? e.responseText:(e['error'] != undefined?e['error']:"")));
       });
     })
    ;

    tree
     .jstree(true)
     .settings.core.check_callback = opt['readonly'] ? false : function(operation, node, node_parent, node_position, more) {
       if(operation === 'rename_node') {
         if(node_parent.text == node_position) { return false; };
         for(let i=0; i < node_parent['children'].length; i++) {
           let child_id=node_parent['children'][i];
           let child_node=this.get_node(child_id);
           if(child_node.text == node_position) { return false; };
         };
       } else if(operation === 'move_node') {
         if(node_parent.text == node.text) { return false; };
         for(let i=0; i < node_parent['children'].length; i++) {
           let child_id=node_parent['children'][i];
           let child_node=this.get_node(child_id);
           if(child_node.text == node.text) { return false; };
         };

       }; 
       return true;
     }
    ;
  });

};

function process_R() {
  unwatch();
  if(!$R || $R['action'] == "ipv4") {
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

  window.onerror = function AllErrorsHandler(errorMsg, url, lineNumber) {
    WATCH=false;
    alert("Error occured: " + errorMsg + "\nIn: "+url+"\nAt: "+ lineNumber);//or any message
    return false;
  };

  $(document).tooltip({classes: { "ui-tooltip": "wspre"}});

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
   .append( $(DIV).myid("debug")
     .css({
       "position": "absolute", "right": "1em", "top": "1em", "width": "600px", "height": "600px",
       "border": "1px solid black",
       "overflow": "scroll",
       "white-space": "pre"
     })
   )
   .append( $(DIV).myid("led")
     .css({
       "position": "absolute", "right": "0em", "top": "0em", "width": "1em", "height": "1em",
       "border": "1px solid black",
       "z-index": 1000000
     })
     .click(function() {
       $("#debug").toggle();
     })
   )
   .append( $(DIV).myid("page_title")
     .css({
       "position": "absolute", "right": "0em", "top": "0em", "left": "0em",
       "text-align": "center", "font-size": "3em"
     })
   )
   .append( $(DIV)
     .css({
       "position": "fixed", "bottom": "0em", "left": "0em", "width": "auto", "height": "auto",
       "z-index": 1000000
     })
     .append( $(DIV)
       .css({"border": "1px solid black", "display": "inline-block", "background-color": "white"})
       .css({"padding": "0.2em"})
       .append( $(LABEL).text("W")
         .click(function() {
           $("#watch_debug").toggle();
         })
       )
     )
     .append( $(DIV).myid("watch_debug")
       .css({"padding": "0.2em"})
       .css({"border": "1px solid black", "background-color": "white"})
       .css({"white-space": "pre"})
       //.hide()
     )
   )
   .append( $(DIV).myid("calc")
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
     .append( $(DIV).myid("calc_text")
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
    ud=data['ok'];
    if(data['ok']['status'] == "unauth") {
      showLoginWindow(data['ok']['providers'], "Необходимо пройти авторизацию.");
    } else {

      let menu_bar = $(DIV).myid("top_menu")
       .css({"border": "1px solid lightgray", "display": "inline-block", "margin-left": "5px", "padding": "5px", "background-color": "white"})
       //.hide()
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
       .append( $(DIV).myid("user_info")
         .css({"border": "1px solid lightgray", "display": "inline-block", "margin-left": "5px", "padding": "5px", "background-color": "white"})
         .hide()
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
           user_edit(ud['user']['user_id'], {'allow_groups_change': true}, function() {
             location.reload(true);
           });
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

      $("#user_info").append( $(SPAN).text(data['ok']['user']['user_name']) );


      if(data['ok']['user']['user_state'] < 1) {
        let message;
        switch(Number(data['ok']['user']['user_state'])) {
        case 0:
          message="Пользователь отключен администратором.";
          break;
        case -1:
          message="Пользователь добавлен автоматически.\nОбратитесь к администратору для активации.";
          break;
        default:
          message="Пользователь удален администратором.";
        };

        message += "\nId пользователя: "+data['ok']['user']['user_id'];

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
        $(DIV).myid("contents")
         .css({"margin-top": "3em"})
         .appendTo("BODY")
        ;
        menu_bar
         .append( $(SPAN).addClass("ui-button").text("IPv4")
           .css({"padding": "0px 0.3em", "margin-left": "10px"})
           .click(function() {
             $R={"action": "ipv4"};
             process_R();
           })
         )
        ;

        menu_bar
         .append( $(SPAN).addClass("ui-button").text("Группы")
           .css({"padding": "0px 0.3em", "margin-left": "10px"})
           .click(function() {
             groups_list([], [], { "allow_add": has_right(R_SUPER), "allow_edit": has_right(R_SUPER), "allow_delete": has_right(R_SUPER), "allow_user_info_btn": false });
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

        menu_bar
         .append( $(SPAN).addClass("ui-button").text("VLAN/BDs")
           .css({"padding": "0px 0.3em", "margin-left": "10px"})
           .click(function() {
             //vlans_list(undefined, {});
             vlans_list([], {"return": "any"}, function(ret_data){ $("#debug").text(jstr(ret_data)); });
           })
         )
        ;

        menu_bar
         .append( $(SPAN).addClass("ui-button").text("Шаблоны")
           .css({"padding": "0px 0.3em", "margin-left": "10px"})
           .click(function() {
             //vlans_list(undefined, {});
             templates_list({});
           })
         )
        ;

        menu_bar
         .append( $(SPAN).addClass("ui-button").text("Сайты")
           .css({"padding": "0px 0.3em", "margin-left": "10px"})
           .click(function() {
             //vlans_list(undefined, {});
             sites_list(undefined, {}, function() {});
           })
         )
        ;

//        process_R();
sites_list(undefined, { "readonly": false}, function(list) {
  alert(list);
});
      };
    };
  });
});
