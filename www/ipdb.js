'use strict';

var body;
var workarea;
var fixed_div;
var user_self_sub="none";
var user_self_id;

var g_range_bar_width = 10;
var g_range_bar_margin = 5;

var global_mouse_down=false;

var g_sorting = false;
var g_autosave = true;
var g_autosave_changes = 0;
var g_autosave_timeout = 500; //ms

var g_default_range_style = {"background-color": "black"};
var g_default_ext_range_style = {"color": "black"};
var g_default_range_icon = "ui-icon-arrow-2-n-s";
var g_default_range_icon_style = {"color": "black"};

var g_vlan_css = {"border": "1px solid black", "padding-left": "0.2em", "padding-right": "0.2em", "background-color": "#FAFAFF"};

var g_show_net_info = false;
var g_show_vdom_info = false;

var g_edit_all = false;

var initial_g_name = "usr_netapp_ipdb_";

var net_cols_ids;

var g_data; //resets by main pages

var usedonly = false;
/* fetched from consts.js node in http_server.go
const R_NAME = 1;
const R_VIEW_NET_INFO = 2;
const R_VIEW_NET_IPS = 4;
const R_EDIT_IP_VLAN = 8;
const R_IGNORE_R_DENY = 16;
const R_MANAGE_NET = 32;
const R_DENYIP = 64;
const ADMIN_GROUP = "usr_netapp_ipdb_appadmins";

const g_rights = {
  "1": {
    "descr": "Просмотр имени сети в списке сетей",
    "label": "ПрИмнСет",
    "required_by": [
      2,
      4,
      8,
      32
    ],
    "used_in": [
      "ext_v4net_range",
      "v4net_acl"
    ]
  },
  "16": {
    "descr": "Игнорировать запрет в диапазонах",
    "label": "ИгнорЗпр",
    "required_by": [],
    "used_in": [
      "ext_v4net_range",
      "v4net_acl"
    ]
  },
  "2": {
    "descr": "Просмотр информации о сети, кроме списка IP адресов",
    "label": "ПрИнфСет",
    "required_by": [
      32
    ],
    "used_in": [
      "ext_v4net_range",
      "v4net_acl"
    ]
  },
  "32": {
    "descr": "Занятие, редактирование, освобождение сети",
    "label": "ИзмнСети",
    "required_by": [],
    "used_in": [
      "ext_v4net_range",
      "v4net_acl"
    ]
  },
  "4": {
    "descr": "Просмотр IP адресов или VLAN-ов",
    "label": "ПрАдрVLN",
    "required_by": [
      8,
      32
    ],
    "used_in": [
      "ext_v4net_range",
      "v4net_acl",
      "vlan_range"
    ]
  },
  "64": {
    "descr": "Запрет занимать, редактировать, удалять IP/VLAN в диапазоне",
    "label": "ЗпртРедт",
    "required_by": [],
    "used_in": [
      "int_v4net_range",
      "vlan_range"
    ]
  },
  "8": {
    "descr": "Занятие, редактирование, освобождение IP адресов или VLAN-ов",
    "label": "ИзмАдрVL",
    "required_by": [
      32
    ],
    "used_in": [
      "ext_v4net_range",
      "v4net_acl",
      "vlan_range",
      "int_v4net_range"
    ]
  }
};
*/

let r_keys = keys(g_rights);
r_keys.sort(function(a, b) { return Number(a) - Number(b); });

function gen_code() {
  let code_chars="qwertyuiopasdfghjkzxcvbnmQWERTYUPASDFGHJKLZXCVBNM23456789";
  let code = "";

  for(let i=0; i < 32; i++) {
    let idx = Math.floor(Math.random() * code_chars.length);
    code += code_chars.charAt(idx);
  };

  return code;
};

function debugLog(text) {
  if(!DEBUG) return;

  $("#debug_win").text( $("#debug_win").text() + "\n" + text);
  $("#debug_win").scrollTop($("#debug_win").prop("scrollHeight"));
};

function save_local(key, value) {
  localStorage.setItem(key+"_"+user_self_sub, JSON.stringify(value));
};

function del_local(key) {
  if(typeof(key) === 'string') {
    localStorage.removeItem(key+"_"+user_self_sub);
  } else if(key instanceof RegExp) {
    let keys=[];
    for(let i=0; i < localStorage.length; i++) {
      if(localStorage.key(i).match(key)) {
        keys.push(localStorage.key(i));
      };
    };
    for(let i in keys) {
      localStorage.removeItem(keys[i]);
    };
  };
};

function get_local(key, on_error=undefined) {
  let js=localStorage.getItem(key+"_"+user_self_sub);
  if(js == undefined || js == "null") return on_error;
  try {
    return JSON.parse(localStorage.getItem(key+"_"+user_self_sub));
  } catch(e) {
    return on_error;
  };
};

function sort_by_string_key(arr, obj, key, asc=true) {
  if(asc) {
    arr.sort(function(a, b) {
      return String(obj[a][key]).toLowerCase().localeCompare( String(obj[b][key]).toLowerCase() );
    });
  } else {
    arr.sort(function(b, a) {
      return String(obj[a][key]).toLowerCase().localeCompare( String(obj[b][key]).toLowerCase() );
    });
  };
};

function sort_by_number_key(arr, obj, key, asc=true) {
  if(asc) {
    arr.sort(function(a, b) {
      return num_compare(String(obj[a][key]).toLowerCase(), String(obj[b][key]).toLowerCase());
    });
  } else {
    arr.sort(function(b, a) {
      return num_compare(String(obj[a][key]).toLowerCase(), String(obj[b][key]).toLowerCase());
    });
  };
};

function num_compare(a, b) {
  let aa=a.split(/(\d+)/);
  let ba=b.split(/(\d+)/);

  while(aa.length > 0 && ba.length > 0) {
    let av=aa.shift();
    let bv=ba.shift();
    if(isNaN(av) && !isNaN(bv)) {
      return 1;
    } else if(isNaN(bv) && !isNaN(av)) {
      return -1;
    } else if(isNaN(av) && isNaN(bv)) {
      let cres=av.localeCompare(bv);
      if(cres != 0) return cres;
    } else {
      if(Number(av) > Number(bv)) {
        return 1;
      } else if(Number(av) < Number(bv)) {
        return -1;
      };
    };
  };

  if(aa.length == ba.length) {
    return 0;
  } else if(aa.length > ba.length) {
    return 1;
  } else {
    return -1;
  };
};

function wdhm(time) {
  time=Math.floor(time);
  let w=Math.floor(time / (7*24*60*60));
  time = time - w*(7*24*60*60);

  let d=Math.floor(time / (24*60*60));
  time = time - d*(24*60*60);

  let h=Math.floor(time / (60*60));
  time = time - h*(60*60);

  let m=Math.floor(time / 60);
  let s=time - m*60;

  let ret="";
  if(w > 0) {
    ret = String(w)+" н. ";
  };
  if(d > 0 || w > 0) {
    ret += String(d)+" д. ";
  };
  if(h > 0 || d > 0 || w > 0) {
    ret += String(h)+" ч. ";
  };
  if(m > 0 || h > 0 || d > 0 || w > 0) {
    ret += String(m)+" м. ";
  };

  ret += String(s)+" с.";

  return ret;
};

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
const v4len2maskN=[
  0n, //0.0.0.0
  2147483648n, //128.0.0.0
  3221225472n, //192.0.0.0
  3758096384n, //224.0.0.0
  4026531840n, //240.0.0.0
  4160749568n, //248.0.0.0
  4227858432n, //252.0.0.0
  4261412864n, //254.0.0.0
  4278190080n, //255.0.0.0
  4286578688n, //255.128.0.0
  4290772992n, //255.192.0.0
  4292870144n, //255.224.0.0
  4293918720n, //255.240.0.0
  4294443008n, //255.248.0.0
  4294705152n, //255.252.0.0
  4294836224n, //255.254.0.0
  4294901760n, //255.255.0.0
  4294934528n, //255.255.128.0
  4294950912n, //255.255.192.0
  4294959104n, //255.255.224.0
  4294963200n, //255.255.240.0
  4294965248n, //255.255.248.0
  4294966272n, //255.255.252.0
  4294966784n, //255.255.254.0
  4294967040n, //255.255.255.0
  4294967168n, //255.255.255.128
  4294967232n, //255.255.255.192
  4294967264n, //255.255.255.224
  4294967280n, //255.255.255.240
  4294967288n, //255.255.255.248
  4294967292n, //255.255.255.252
  4294967294n, //255.255.255.254
  4294967295n //255.255.255.255
];
function cidr_valid(cidr) {
  let m=String(cidr).match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
  if(m === null) return false;
  if(m[1] > 255 || m[2] > 255 || m[3] > 255 || m[4] > 255 || m[5] > 32) return false;

  let ip=v4oct2long(m[1], m[2], m[3], m[4]);
  let net = (ip & v4len2mask[ Number(m[5]) ]) >>> 0;
  if(ip != net) return false;

  return true;
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
  if(m == null || m.length != 5 || Number(m[1]) > 255 || Number(m[2]) > 255 ||
     Number(m[3]) > 255 || Number(m[4]) > 255
  ) {
    return false;
  } else {
    return(v4oct2long(m[1], m[2], m[3], m[4]));
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

function ip4net(ip, masklen) {
  return Number(BigInt(ip) & v4len2maskN[masklen]);
};

function net_mask_wc(net, masklen) {
  return v4long2ip(net)+"/"+masklen+" ("+v4long2ip(v4len2mask[masklen])+" "+v4long2ip((~v4len2mask[masklen]) >>> 0) + ")";
};

function autosave_normalize(elm) {
  let elm_data = elm.data("autosave_data");
  if(elm_data === undefined) { error_at(); return false; };
  if(elm_data['object'] === undefined) { error_at(); return false; };

  let value;

  switch(elm_data['object']) {
  case 'group':
    switch(elm_data['prop']) {
    case 'g_name':
      return String(elm.val()).trim().toLowerCase();
      break;
    case 'g_descr':
      return String(elm.val()).trim();
      break;
    default:
      return elm.val();
    };
    break;
  case 'ip_value':
    return elm.val();
    break;
  case 'ip':
    return elm.val();
    break;
  case 'net':
    switch(elm_data['prop']) {
    case 'v4net_name':
      return String(elm.val()).trim();
      break;
    default:
      return elm.val();
    };
    break;
  case 'vdom':
    switch(elm_data['prop']) {
    case 'vd_name':
      return String(elm.val()).trim();
      break;
    default:
      return elm.val();
    };
    break;
  case 'vlan_value':
    switch(elm_data['prop']) {
    case 'vlan_name':
      return String(elm.val()).trim();
      break;
    case 'vlan_descr':
      return String(elm.val()).trim();
      break;
    default:
      error_at("Unknown object: "+elm_data['object']+" prop: "+elm_data['prop']);
    };
    return elm.val();
    break;
  };
  error_at("Unknown object: "+elm_data['object']+" prop: "+elm_data['prop']);
};

function saveable_check(elm) {
  let value = autosave_normalize(elm);
  if(value === undefined) { error_at(); return false; };
  let elm_data = elm.data("autosave_data");
  if(elm_data === undefined) { error_at(); return false; };
  if(elm_data['object'] === undefined) { error_at(); return false; };

  switch(elm_data['object']) {
  case 'group':
    let id = elm_data['id'];
    if(id === undefined) { error_at(); return false; };
    switch(elm_data['prop']) {
    case 'g_name':
      if(!value.match(/^\S.*\S$/)) {
        return false;
      } else if(value == ADMIN_GROUP) {
        return false;
      } else {
        let found = false;
        elm.closest(".table").find(".tr").each(function() {
          let row_id = $(this).data("id");
          if(row_id === undefined) { error_at(); return false; };
          let row_val = autosave_normalize($(this).find(".g_name"));
          if(row_val === undefined) { error_at(); return false; };
          if(row_id != id && row_val === value) {
            found = true;
            return false;
          };
        });
        if(found) {
          return false;
        } else {
          return true;
        };
      };
      break;
    default:
      return true;
    };
    break;
  case 'ip_value':
    return true;
  case 'ip':
    return true;
  case 'net':
    return true;
  case 'vdom':
    return true;
  case 'vlan_value':
    switch(elm_data['prop']) {
    case 'vlan_name':
      let found = false;
      let vlan_number = elm.closest("TR").data("row_data")['vlan_number'];
      elm.closest("TABLE").find("TR.row").each(function() {
        let row_data = $(this).data("row_data");
        if(row_data['is_taken'] && String(row_data['vlan_name']).trim() === value &&
           row_data['vlan_number'] != vlan_number
        ) {
          found = true;
          return false;
        };

      });
      if(found) {
        return false;
      };
      break;
    };
    return true;
  };
  error_at("Unknown object: "+elm_data['object']+" prop: "+elm_data['prop']);
  return false;
};

$.fn.saveable=function(data) {
  let timeout = (g_autosave_timeout===undefined?500:g_autosave_timeout);
  $(this)
   .addClass("autosave")
   .data("autosave_data", data)
   .data("autosave_changed", false)
   .data("autosave_prev", autosave_normalize($(this)))
   .data("autosave_saved", autosave_normalize($(this)))
   .inputStop(timeout)
   .on("input_stop", function() {

     let normalized_val = autosave_normalize($(this));

     if(!saveable_check($(this))) {
       $(this).css({"background-color": "lightcoral"});
       return;
     } else {
       $(this).css({"background-color": "white"});
     };

     let saved_val = $(this).data("autosave_saved");
     let already_changed = $(this).data("autosave_changed");

     if(already_changed) {
       if(saved_val === normalized_val) {
         g_autosave_changes--;
         $(this).data("autosave_changed", false);
         $(this).closest(".unsaved_elm").removeClass("unsaved");
       };
     } else {
       if(saved_val !== normalized_val) {
         g_autosave_changes++;
         $(this).data("autosave_changed", true);
         $(this).closest(".unsaved_elm").addClass("unsaved");
       };
     };

     if(g_autosave_changes < 0) {
       error_at();
       return;
     } else if(g_autosave_changes == 0) {
       $("#autosave_btn").css({"color": "gray"});
     } else {
       $("#autosave_btn").css({"color": "yellow"});
       if(g_autosave) {
         save_all();
       };
     };
   })
  ;
  return $(this);
};

function ellipsed(text, chars) {
  let ret = String(text);
  if(ret.length > (chars-3)) {
    ret = ret.substring(0, chars-3);
    ret += "...";
  };
  return ret;
};

var userinfo = {};

$( document ).ready(function() {
 
  usedonly = getUrlParameter("usedonly", false);

  //BEGIN begin
  window.onerror=function(errorMsg, url, lineNumber) {
    alert("Error occured: " + errorMsg + ", at line: " + lineNumber);//or any message
    return false;
  };

  $(document)
   .on("mousedown mouseup mousemove", function(e) {
     global_mouse_down = e.originalEvent.buttons === undefined ? e.which === 1 : e.buttons === 1;
   })
  ;

  $(window).on('beforeunload', function() {
    if(g_autosave_changes > 0) {
      return "На странице есть несохраненные поля. Подтвердите уход.";
    } else {
      return undefined;
    };
  });

  $(document).click(function() { $("UL.popupmenu").remove(); });
  $(document).keyup(function(e) {
    if (e.key === "Escape") { // escape key maps to keycode `27`
      $("UL.popupmenu").remove();
      $(".tooltip").remove();
    };
  });

  $("BODY").append (
    $(DIV).css({"position": "fixed", "right": "0.5em", "top": "0.5em", "min-width": "2em",
                "border": "1px solid black", "background-color": "lightgrey"
    }).prop("id", "indicator").text("Запуск интерфейса...")
  );

  if(version.match(/devel/)) {
    $("BODY")
     .append ( $(DIV).css({"position": "fixed", "right": "1em", "bottom": "1em", "color": "red" }).text("DEVELOPMENT"))
     .append ( $(DIV).css({"position": "fixed", "left": "1em", "bottom": "1em", "color": "red" }).text("DEVELOPMENT"))
    ;
  };

  $(document).ajaxComplete(function() {
    $("#indicator").text("Запрос завершен").css("background-color", "lightgreen");
  });

  $(document).ajaxStart(function() {
    $("#indicator").text("Запрос ...").css("background-color", "yellow");
  });

  //$( document ).tooltip({ items: ".tooltip[title]", show: null });
  body=$( "body" );
  body.css({"height": "100%", "margin": "0"});
  $("HTML").css({"height": "100%", "margin": "0"});

  if(DEBUG) {
    body
     .append( $(DIV).prop("id", "debug_win")
       .addClass("wsp")
       .css({"position": "fixed", "bottom": "1em", "right": "1em", "width": "35em",
             "top": "15em", "overflow": "auto", "border": "1px black solid", "background-color": "white",
             "z-index": 100000}
       )
       .toggle(false)
     )
     .append( $(LABEL)
       .prop("id", "debug_clear_btn")
       .css({"position": "fixed", "bottom": "0em", "right": "3em",
             "z-index": 100001}
       )
       .append( $(LABEL)
         .addClass(["ui-icon", "ui-icon-delete", "button"])
         .click(function() {
           $("#debug_win").contents().filter(function(){
              return (this.nodeType == 3);
           }).remove();
         })
       )
       .toggle(false)
     )
     .append( $(LABEL)
       .css({"position": "fixed", "bottom": "0em", "right": "1em",
             "z-index": 100001}
       )
       .append( $(LABEL)
         .addClass(["ui-icon", "ui-icon-arrowthick-2-n-s", "button"])
         .click(function() {
           $("#debug_win,#debug_clear_btn").toggle();
         })
       )
     )
    ;
  };


  run_query({"action": "userinfo"}, function(res) {

    userinfo = res["ok"];

    user_self_sub = userinfo["sub"];
    user_self_id = userinfo["id"];

    g_autosave = get_local("autosave", g_autosave);
    g_autosave_timeout = get_local("autosave_timeout", g_autosave_timeout);

    let menu = $(DIV).addClass("menu");
    body.append( menu );

    workarea = $(DIV).prop("id", "workarea").addClass("workarea");
    fixed_div = $(DIV).prop("id", "fixed_div").addClass("fixed_div");

    body.append( workarea );

    menu
     .append( userinfo_btn() )
     .append( $(SPAN)
       .css({"border": "1px solid #444444", "padding": "0.3em"})
       .addClass("ns")
       .append( $(LABEL).text("Автосохранение: ")
         .prop({"for": "autosave"})
       )
       .append( $(INPUT)
         .prop({"id": "autosave", "type": "checkbox", "checked": g_autosave})
         .on("change", function() {
           g_autosave = $(this).is(":checked");
           save_local("autosave", g_autosave);
           if(g_autosave) {
             save_all();
           };
         })
       )
       .append( $(LABEL).addClass("min1em") )
       .append( $(LABEL)
         .prop({"id": "autosave_btn"})
         .addClass(["button", "ui-icon", "ui-icon-save"])
         .css({"color": "gray"})
         .title("Сохранить")
         .click(save_all)
       )
     )
     .append( $(SPAN).addClass("bigbutton").text("IPDB")
       .click( function() {
         //actionFront();
         window.location = "?action=front"+(DEBUG?"&debug":"");
       })
     )
    ;

    if(userinfo["is_admin"]) {
      menu
       .append( $(SPAN).addClass("bigbutton").text("Группы доступа")
         .click( function() {
           //actionGroups();
           window.location = "?action=groups"+(DEBUG?"&debug":"");
         })
       )
      ;
    };

    if(userinfo["has_vlans_access"]) {
      menu
       .append( $(SPAN).addClass("bigbutton").text("VLAN")
         .click( function() {
           //actionVlanDomains();
           window.location = "?action=vlan_domains"+(DEBUG?"&debug":"");
         })
       )
      ;
    };

    menu.append( fixed_div )

    let action=getUrlParameter("action");
    switch(action) {
    case "front":
      actionFront();
      break;
    case "groups":
      actionGroups();
      break;
    case "nav_v4":
      actionNav4();
      break;
    case "view_v4":
      actionView4();
      break;
    case "vlan_domains":
      actionVlanDomains();
      break;
    case "view_vlan_domain":
      actionViewVlanDomain();
      break;
    default:
      window.location = "?action=front"+(DEBUG?"&debug":"");
      //history.pushState(undefined, undefined, "?action=front"+(DEBUG?"&debug":""));
      //actionFront();
    };

  });
});

function userinfo_btn() {
  let ret=$(DIV)
   .addClass("userinfo")
   .css({"display": "inline-block", "padding": "0.5em"})
   .append( $(LABEL)
     .addClass(["button", "ui-icon", "ui-icon-user"])
     .css({"margin-right": "0.5em"})
     .click(function() { $(this).closest(".userinfo").find(".hideable").toggle(); })
   )
   .append( $(DIV)
     .css({"display": "inline-block", "position": "absolute", "top": "0em",
            "left": "2em", "background-color": "white", "z-index": 1000000,
            "border": "1px solid black", "padding": "0.5em"}
     )
     .addClass("hideable")
     .hide()
     .append( $(SPAN).text(userinfo["name"]).css({"margin-right": "0.5em"}) )
     .append( $(SPAN).text(userinfo["login"]).css({"margin-right": "0.5em"}) )
     .append( $(LABEL).addClass(["ui-icon", "ui-icon-info", "button"]).title(jstr(userinfo))
       .click(function() { show_dialog(jstr(userinfo)); })
     )
     .append( $(LABEL).css({"margin-left": "0.2em"}) )
     .append( $(LABEL).title("Выход")
       .addClass(["button", "ui-icon", "ui-icon-logout"])
       .click(function() { window.location = "/logout"; })
     )
   )
  ;
  return ret;
};

function save_all() {
  debugLog("AUTOSAVING");
  $("#autosave_btn").css({"color": "green"});

  let queue = [];
  let queue_elements = [];

  let has_error = false;

  $(".autosave").each(function() {
    let value = autosave_normalize($(this));
    if(!saveable_check($(this))) {
      has_error = true;
      return false;
    };

    if(value !== $(this).data("autosave_saved")) {
      queue.push({"value": value, "data": $(this).data("autosave_data")});
      queue_elements.push({"elm": $(this), "val": value, "data": $(this).data("autosave_data")});
    };
  });

  if(has_error) {
    $("#autosave_btn").css({"color": "red"});
    return;
  };

  debugLog(jstr(queue));

  if(queue.length == 0) {
    $("#autosave_btn").css({"color": "green"});
    return;
  };

  run_query({"action": "save_all", "queue": queue}, function(res) {

    if(res['ok']['done'] === undefined) {
      error_at();
      return;
    };

    let highlight = $([]);

    for(let i in queue_elements) {
      let qelm = queue_elements[i]['elm'];
      let qval = queue_elements[i]['val'];
      let qdata = queue_elements[i]['data'];
      let tr;

      qelm.data("autosave_saved", qval);
      qelm.data("autosave_changed", false);
      switch(qdata['object']) {
      case "ip_value":
        tr = qelm.closest(".row");
        let ipdata = tr.data("ipdata");
        ipdata['values'][qdata['col_id']]['v'] = qval;
        ipdata['values'][qdata['col_id']]['ts'] = unix_timestamp();
        ipdata['values'][qdata['col_id']]['u_id'] = user_self_id;
        tr.data("ipdata", ipdata);
        let edit_state = qelm.hasClass("ip_edit");
        let focus = qelm.is(":focus");
        let new_elm = ip_val_elm(ipdata, qdata['col_id'], edit_state);
        qelm.replaceWith( new_elm );
        if(focus) new_elm.focus();
        highlight = highlight.add(new_elm);
        break;
      case "vlan_value":
        tr = qelm.closest(".row");
        let row_data = tr.data("row_data");
        row_data[qdata['prop']] = qval;
        row_data['ts'] = unix_timestamp();
        row_data['u_id'] = user_self_id;
        tr.data("row_data", row_data);
        highlight = highlight.add(qelm);
        break;
      default:
        highlight = highlight.add(qelm);
      };

      if(qdata['_after_save'] !== undefined) {
        qdata['_after_save'](qelm, qval);
      };
    };
    highlight.animateHighlight("lightgreen", 200);
    g_autosave_changes = 0;
    $("#autosave_btn").css({"color": "green"});
    $(".unsaved").removeClass("unsaved");
  });
};

function actionFront() {
  //history.pushState(undefined, undefined, "?action=front"+(DEBUG?"&debug":""));
  workarea.empty();
  fixed_div.empty();
  run_query({"action": "get_front"}, function(res) {

    let nav_div = $(DIV).css({"display": "inline-block", "vertical-align": "top"})
     .append( $(SPAN).text("Навигация: ") )
     .append( $(A).prop({"href": "?action=nav_v4&net=0&masklen=0"+(DEBUG?"&debug":"")}).text("0.0.0.0/0") )
     .append( $(SPAN).text(" (") )
     .append( $(A)
       .prop({"href": "?action=nav_v4&net=0&masklen=0&usedonly"+(DEBUG?"&debug":"")})
       .text("исп.").title("Только используемые")
     )
     .append( $(SPAN).text(")") )
     .append( $(BR) )
     .append( $(SPAN).text("Перейти: ") )
     .append( $(INPUT)
       .prop({"type": "search", "placeholder": "x.x.x.x/x", "id": "ipv4_goto"})
       .enterKey(function() {
         $("#ipv4_goto_btn").trigger("click")
       })
     )
     .append( $(LABEL).text(">").title("Перейти к отображению сети").addClass("button")
       .prop({"id": "ipv4_goto_btn"})
       .click(function() {
         $("#ipv4_goto").animateHighlight("green", 500);
       })
     )
     .append( $(BR) )
     .append( $(SPAN).text("Поиск: ") )
     .append( $(INPUT)
       .prop({"type": "search", "id": "search_string"})
       .enterKey(function() {
         $("#search_btn").trigger("click")
       })
     )
     .append( $(LABEL).text(">").title("Перейти к отображению сети").addClass("button")
       .prop({"id": "search_btn"})
       .click(function() {
         $("#search_string").animateHighlight("green", 500);
       })
     )
     .append( $(BR) )
     .appendTo( workarea )
    ;

    if(res['ok']['v4favs'] !== undefined && Array.isArray(res['ok']['v4favs']) && res['ok']['v4favs'].length > 0) {
      let v4favs = $(DIV)
       .css({"display": "inline-block", "vertical-align": "top"})
       .append( $(DIV)
         .append( $(SPAN).text("Избранное") )
       )
      ;

      res['ok']['v4favs'].sort(function(a,b) { return a['v4net_addr']-b['v4net_addr']; });

      for(let i=0; i < res['ok']['v4favs'].length; i++) {
        let mask_bits = v4len2mask[ res['ok']['v4favs'][i]['v4net_mask'] ];
        let wildcard_bits = (~mask_bits) >>> 0;
        v4favs
         .append( $(DIV)
           .addClass("wsp")
           .addClass("fav_row")
           .append( $(A).prop({"href": "?action=nav_v4&net="+res['ok']['v4favs'][i]['v4net_addr']+"&masklen="+
                                        res['ok']['v4favs'][i]['v4net_mask']+(DEBUG?"&debug":"")})
             .text( v4long2ip(res['ok']['v4favs'][i]['v4net_addr'])+"/"+res['ok']['v4favs'][i]['v4net_mask'] )
             .title( "Mask: "+v4long2ip(mask_bits)+"\n"+"Wildcard: "+v4long2ip(wildcard_bits) )
           )
           .append( $(SPAN).text(" (") )
           .append( $(A).prop({"href": "?action=nav_v4&usedonly&net="+res['ok']['v4favs'][i]['v4net_addr']+"&masklen="+
                                        res['ok']['v4favs'][i]['v4net_mask']+(DEBUG?"&debug":"")})
             .text( "исп." )
             .title("Только используемые")
           )
           .append( $(SPAN).text(")") )
           .append( $(SPAN).addClass("min05em") )
           .append( $(LABEL).addClass(["button", "ui-icon", "ui-icon-trash"])
             .css({"font-size": "smaller"})
             .title("Убрать из избранного")
             .data("net", res['ok']['v4favs'][i]['v4net_addr'])
             .data("masklen", res['ok']['v4favs'][i]['v4net_mask'])
             .click(function() {
               let net = $(this).data("net");
               let masklen = $(this).data("masklen");
               let row = $(this).closest(".fav_row");
               show_confirm("Подтвердите удаление сети из избранного", function() {
                 run_query({"action": "fav_v4", "net": String(net), "masklen": String(masklen), "fav": 0}, function(res) {
                   row.remove();
                 });
               });
             })
           )
         )
        ;
      };

      v4favs.appendTo( workarea );
    };
    if(res['ok']['v4accessible'] !== undefined && Array.isArray(res['ok']['v4accessible']) &&
       res['ok']['v4accessible'].length > 0
    ) {
      let v4accessible = $(DIV)
       .css({"display": "inline-block", "vertical-align": "top"})
       .append( $(DIV)
         .append( $(SPAN).text("С доступом") )
       )
      ;

      res['ok']['v4accessible'].sort(function(a,b) { return a['v4net_addr']-b['v4net_addr']; });

      for(let i=0; i < res['ok']['v4accessible'].length; i++) {
        let mask_bits = v4len2mask[ res['ok']['v4accessible'][i]['v4net_mask'] ];
        let wildcard_bits = (~mask_bits) >>> 0;
        v4accessible
         .append( $(DIV)
           .addClass("wsp")
           .append( $(A)
             .prop({"href": "?action=nav_v4&net="+res['ok']['v4accessible'][i]['v4net_addr']+"&masklen="+
                            res['ok']['v4accessible'][i]['v4net_mask']+(DEBUG?"&debug":"")}
             )
             .text( v4long2ip(res['ok']['v4accessible'][i]['v4net_addr'])+"/"+
                    res['ok']['v4accessible'][i]['v4net_mask']
             )
             .title( "Mask: "+v4long2ip(mask_bits)+"\n"+"Wildcard: "+v4long2ip(wildcard_bits) )
           )
           .append( $(SPAN).text(" (") )
           .append( $(A)
             .prop({"href": "?action=nav_v4&usedonly&net="+res['ok']['v4accessible'][i]['v4net_addr']+
                            "&masklen="+res['ok']['v4accessible'][i]['v4net_mask']+(DEBUG?"&debug":"")}
             )
             .text( "исп." )
             .title("Только используемые")
           )
           .append( $(SPAN).text(")") )
         )
        ;
      };

      v4accessible.appendTo( workarea );
    };
  });
};

function actionGroups() {
  //history.pushState(undefined, undefined, "?action=groups"+(DEBUG?"&debug":""));
  workarea.empty();
  fixed_div.empty();

  let table = $(DIV)
   .addClass("table")
   .appendTo( workarea )
  ;

  table
   .append( $(DIV)
     .addClass("thead")
     .append( $(DIV)
       .addClass("th")
       .append( $(SPAN)
         .text("id")
         .title("g_id в базе данных")
       )
     )
     .append( $(DIV)
       .addClass("th")
       .append( $(SPAN)
         .text("sAMAccountName")
         .title("Имя группы \"pre-Windows 2000\"")
       )
     )
     .append( $(DIV)
       .addClass("th")
       .append( $(SPAN)
         .text("Описание")
         .title("Назначение группы")
       )
     )
     .append( $(DIV)
       .addClass("th")
       .append( $(LABEL).html("&nbsp;")
       )
     )
   )
   .append( $(DIV)
     .addClass("tfoot")
     .append( $(DIV)
       .addClass("td")
       .append( $(LABEL).html("&nbsp;")
       )
     )
     .append( $(DIV)
       .addClass("td")
       .append( $(INPUT)
         .css({"width": "20em"})
         .val(initial_g_name)
         .addClass("g_name")
         .data("autosave_data", {"object": "group", "prop": "g_name"})
       )
     )
     .append( $(DIV)
       .addClass("td")
       .append( $(INPUT)
         .css({"width": "50em"})
         .addClass("g_descr")
         .data("autosave_data", {"object": "group", "prop": "g_descr"})
       )
     )
     .append( $(DIV)
       .addClass("td")
       .append( $(LABEL)
         .addClass(["button", "ui-icon", "ui-icon-plus"])
       )
       .title("Добавить")
       .click(function() {
         let g_name = autosave_normalize($(this).closest(".tfoot").find(".g_name"));
         if(g_name === undefined) error_at();
         g_name = String(g_name).trim().toLowerCase();

         let g_descr = autosave_normalize($(this).closest(".tfoot").find(".g_descr"));
         if(g_descr === undefined) error_at();
         g_descr = String(g_descr).trim();

         if(g_name == initial_g_name || g_name == ADMIN_GROUP || g_name == "Все") {
           $(this).closest(".tfoot").find(".g_name").animateHighlight("red", 500);
           $(this).closest(".tfoot").find(".g_name").focus();
           return;
         };
         let found = undefined;
         $(this).closest(".table").find(".tr").find(".g_name").each(function() {
           if( autosave_normalize($(this)) == g_name) {
             found = $(this);
             return false;
           };
         });
         if( found != undefined ) {
           found.add($(this).closest(".tfoot").find(".g_name")).animateHighlight("red", 500);
           $(this).closest(".tfoot").find(".g_name").focus();
           return;
         };

         let insert_before = $(this).closest(".tfoot");

         run_query({"action": "add_group", "g_name": g_name, "g_descr": g_descr}, function(res) {

           if(res['ok']['gs'] === undefined || !Array.isArray(res['ok']['gs'])) { return; };


           for(let i in res['ok']['gs']) {
             get_group_row(res['ok']['gs'][i], res['ok']['users']).insertBefore(insert_before);
           };
           insert_before.find(".g_name").val(initial_g_name);
           insert_before.find(".g_descr").val("");
           insert_before.find(".g_name").focus();
         });
       })
     )
   )
  ;

  table.find(".tfoot").find(".g_name").focus();

  run_query({"action": "get_groups"}, function(res) {

    if(res['ok']['gs'] === undefined || !Array.isArray(res['ok']['gs'])) { return; };


    for(let i in res['ok']['gs']) {
      if(res['ok']['gs'][i]['any'] == 0 && res['ok']['gs'][i]['g_name'] != ADMIN_GROUP) {
        get_group_row(res['ok']['gs'][i], res['ok']['users']).insertBefore(table.find(".tfoot"));
      };
    };

  });
};

function get_group_row(db_row, users) {
  let id_title = "Добавлено: "+from_unix_time(db_row['added'], false, 'н/д');
  id_title += "\nИзменено: "+from_unix_time(db_row['ts'], false, 'н/д');
  if(users !== undefined && db_row['fk_u_id'] !== null && users[ db_row['fk_u_id'] ] !== undefined) {
    id_title += "\nКем: "+users[ db_row['fk_u_id'] ]['u_name']+" ("+users[ db_row['fk_u_id'] ]['u_login']+")";
  };

  let ret = $(DIV)
   .addClass("tr")
   .addClass("id_data")
   .data("id", db_row['g_id'])
   .data("data", db_row)
   .append( $(DIV)
     .addClass("td")
     .append( $(SPAN).text( db_row['g_id'] )
     )
     .title( id_title )
   )
   .append( $(DIV)
     .addClass("td")
     .append( $(INPUT)
       .css({"width": "20em"})
       .addClass("g_name")
       .val( db_row['g_name'] )
       .saveable({"object": "group", "id": String(db_row['g_id']), "prop": "g_name"})
     )
   )
   .append( $(DIV)
     .addClass("td")
     .append( $(INPUT)
       .css({"width": "50em"})
       .addClass("g_descr")
       .val( db_row['g_descr'] )
       .saveable({"object": "group", "id": String(db_row['g_id']), "prop": "g_descr"})
     )
   )
   .append( $(DIV)
     .addClass("td")
     .append( $(LABEL)
       .addClass(["button", "ui-icon", "ui-icon-delete"])
       .click(function() {
         let elm = $(this);
         let id_elm = elm.closest(".id_data");
         if(id_elm.length == 0) error_at();
         let id = id_elm.data("id");
         if(id === undefined) error_at();
         let g_name = autosave_normalize(elm.closest(".tr").find(".g_name"));
         show_confirm("Подтвердите удаление группы \""+g_name+"\".\nОТМЕНА ОПЕРАЦИИ БУДЕТ НЕВОЗМОЖНА!", function() {
           run_query({"action": "del_group", "id": String(id)}, function(res) {
           
             if(res['ok']['used'] !== undefined) {
               show_confirm_checkbox("ВНИМАНИЕ! Группа \""+g_name+"\" используется\nв "+res['ok']['used']+
                                     " списках доступа.\nУдаление приведет к удалению группы также из списков"+
                                     " доступа.\nОТМЕНА ОПЕРАЦИИ БУДЕТ НЕВОЗМОЖНА!", function() {
                 run_query({"action": "del_group", "id": String(id), "confirmed": 1}, function(_res) {
           
                   if(_res['ok']['done'] === undefined) {
                     error_at();
                     return;
                   };
                   elm.closest(".tr").remove();
                 });
               });
             } else if(res['ok']['done'] === undefined) {
               error_at();
               return;
             } else {
               elm.closest(".tr").remove();
             };
           });
         });
       })
     )
   )
  ;
  return ret;
};

function vrange_title(range) {
  let ret = "";
  ret += range['vr_name'];
  ret += " (id:"+range['vr_id']+")";
  ret += "\n";
  ret += range['vr_start']+"-"+range['vr_stop'];
  ret += "\n";
  ret += "Rights:" + range['rights'];
  ret += "\n";
  ret += range['vr_descr'];
  return ret;
};

function v4range_title(range) {
  let ret = "";
  ret += range['v4r_name'];
  ret += " (id:"+range['v4r_id']+")";
  ret += "\n";
  ret += v4long2ip(range['v4r_start'])+"-"+v4long2ip(range['v4r_stop']);
  ret += "\n";
  ret += "Rights:" + range['rights'];
  ret += "\n";
  ret += range['v4r_descr'];
  return ret;
};
function actionNav4() {
  workarea.empty();
  fixed_div.empty();
  let net = getUrlParameter("net", undefined);
  let masklen = getUrlParameter("masklen", undefined);

  if(net === undefined || ! String(net).match(/^\d+$/) || Number(net) > 4294967295) { error_at(); return; };
  if(masklen === undefined || ! String(masklen).match(/^\d{1,2}$/) || Number(masklen) > 32) { error_at(); return; };

  if(Number(net) != ip4net(net, masklen)) {
    error_at();
    return;
  };

  run_query({"action": "nav_v4", "net": net, "masklen": masklen}, function(res) {

    if(res['ok']['taken'] !== undefined) {
      window.location = "?action=view_v4&net="+net+"&masklen="+masklen+(usedonly?"&usedonly":"")+(DEBUG?"&debug":"");
      return;
    };

    g_data = res['ok'];

    let backlen = 0;
    if(masklen <=8 ) {
      backlen = 0;
    } else if(masklen <= 16) {
      backlen = 8;
    } else if(masklen <= 24) {
      backlen = 16;
    } else {
      backlen = 24;
    };

    fixed_div
     .append( $(A)
       .prop("href", "?action=nav_v4&net="+ip4net(net, backlen)+"&masklen="+backlen+(usedonly?"&usedonly":"")+(DEBUG?"&debug":""))
       .text("<<<")
       .title( "Назад к сети: "+net_mask_wc(net, backlen) )
     )
     .append( $(SPAN).addClass("min1em") )
     .append( $(LABEL).text("Сеть: ") )
     .append( $(SPAN)
       .text( net_mask_wc(net, masklen) )
     )
     .append( $(SPAN).addClass("min1em") )
     .append( $(A)
       .prop("href", "?action=nav_v4&net="+net+"&masklen="+masklen+(!usedonly?"&usedonly":"")+(DEBUG?"&debug":""))
       .text(usedonly?"(Показать все)":"(Только используемые)")
     )
     .append( $(SPAN).addClass("min1em") )
     .append( $(LABEL).text("В избранном: ") )
     .append( $(INPUT).prop({"type": "checkbox", "checked": res['ok']['fav'] == 1})
       .on("change", function() {
         let checked = $(this).is(":checked");
         run_query({"action": "fav_v4", "net": net, "masklen": masklen, "fav": checked?1:0}, function(res) {
         });
       })
     )
    ;

    workarea
     .append( $(DIV)
     )
    ;

    let table = $(DIV).addClass("table")
    ;

    let thead = $(DIV).addClass("thead")
    ;

    thead.append( $(SPAN).addClass("th").text("Сеть") );

    for(let col_mask = Number(masklen)+1; col_mask <= Number(res['ok']['lastmask']); col_mask++) {
      let th = $(SPAN).addClass("th")
       .text("/"+String(col_mask))
       .title( v4long2ip(v4len2mask[col_mask])+" "+v4long2ip((~v4len2mask[col_mask]) >>> 0) )
       .appendTo(thead)
      ;
    };

    for(let i in res['ok']['ranges']) {
      let th = $(SPAN).addClass("th")
       .css({"padding-left": "0.1em", "padding-right": "0.1em"})
       .title(v4range_title(res['ok']['ranges'][i]))
      ;
      if(res['ok']['ranges'][i]['v4r_icon'] != "") {
        let label = $(LABEL)
         .html("&bull;")
         .data("r_i", i)
         .addClass("range_shown")
        ;
        if(res['ok']['ranges'][i]['v4r_style'] != "") {
          try {
            let style = JSON.parse(res['ok']['ranges'][i]['v4r_style']);
            label.css(style);
          } catch(e) {
            //ignore
          };
        };
        label.appendTo(th);
      };
      th.appendTo(thead);
    };

    thead
     .append( $(SPAN).addClass("th")
       .append( !userinfo['is_admin']?$(LABEL):$(LABEL)
         .addClass(["button", "ui-icon", "ui-icon-plus"])
         .title("Создать диапазон")
         .click(function() {
           edit_net_range("ext_v4net_range", undefined);
         })
       )
     )
    ;

    thead.appendTo(table);

    for(let i in res['ok']['rows']) {
      let row = res['ok']['rows'][i];
      let this_net = row['net'];
      let this_net_last_addr = row['last_addr'];
      if(usedonly &&
         res['ok']['rows'][i]['is_taken'] === undefined &&
         res['ok']['rows'][i]['is_part_of_taken'] === undefined &&
         res['ok']['rows'][i]['subnets'] === undefined &&
         true
      ) {
        continue;
      };
      let tr = $(DIV).addClass("tr")
      ;
      tr
       .append( $(SPAN).addClass("td")
         .text(v4long2ip(row["net"]))
       )
      ;

      for(let ci in res['ok']['rows'][i]['cols']) {
        let col_mask = Number(masklen)+Number(ci)+Number(1);
        let td = $(SPAN).addClass("td");

        if(res['ok']['rows'][i]['cols'][ci]['is_net'] !== undefined) {
          if(res['ok']['rows'][i]['cols'][ci]['is_taken'] == undefined) {
            if(res['ok']['rows'][i]['cols'][ci]['is_part_of_taken'] == undefined ) {
              if(col_mask < 32) {
                td
                 .append( $(A)
                   .prop("href", "?action=nav_v4&net="+row['net']+"&masklen="+col_mask+(usedonly?"&usedonly":"")+(DEBUG?"&debug":""))
                   .text("><")
                   .title("Перейти к "+v4long2ip(row["net"])+"/"+col_mask+"\n"+net_mask_wc(row["net"], col_mask))
                 )
                ;
              };
              if(res['ok']['rows'][i]['cols'][ci]['is_busy'] === undefined &&
                 (res['ok']['rows'][i]['cols'][ci]['ranges_rights'] & R_MANAGE_NET) > 0
              ) {
                td
                 .append( $(SPAN).addClass("min1em") )
                 .append( $(LABEL)
                   .addClass(["button", "ui-icon", "ui-icon-plus"])
                   .title("Занять "+v4long2ip(row["net"])+"/"+col_mask+"\n"+net_mask_wc(row["net"], col_mask))
                   .data("take_net", row['net'])
                   .data("take_masklen", col_mask)
                   .click(function() {
                     take_v4net($(this).data("take_net"), $(this).data("take_masklen"));
                   })
                 )
                ;
              };
            };
            if(res['ok']['rows'][i]['cols'][ci]['is_busy']) {
              td.css({"background-color": "gray"});
            };
          } else {
            if((res['ok']['rows'][i]['cols'][ci]['net_rights'] & (R_VIEW_NET_INFO | R_VIEW_NET_IPS)) > 0) {
              td
               .append( $(A)
                 .prop("href", "?action=view_v4&net="+row['net']+"&masklen="+col_mask+(usedonly?"&usedonly":"")+(DEBUG?"&debug":""))
                 .text("V")
                 .title("Просмотр "+v4long2ip(row["net"])+"/"+col_mask+"\n"+net_mask_wc(row["net"], col_mask))
               )
              ;
            };
            td.css({"border-top": "1px solid white"});
          };
          tr.append(td);
        };
        if(res['ok']['rows'][i]['cols'][ci]['is_taken'] !== undefined ||
           res['ok']['rows'][i]['cols'][ci]['is_part_of_taken'] !== undefined ||
           false
        ) {
          td.css({"background-color": "lightgray"});
          if(res['ok']['rows'][i]['is_taken'] !== undefined) {
            td.css({"background-color": "lightgray", "border-top": "1px solid white"});
          };
        };
        tr.append( td );
      };

      for(let r in res['ok']['ranges']) {
        let td = $(SPAN).addClass("td")
         .css({"padding-left": "0.1em", "padding-right": "0.1em"})
         .title(v4range_title(res['ok']['ranges'][r]))
        ;
        if(res['ok']['rows'][i]['ranges'][r]['in_range'] !== undefined) {
          let label_style;
          try {
            label_style = JSON.parse(res['ok']['ranges'][r]['v4r_style']);
          } catch(e) {
            label_style = g_default_ext_range_style;
          };

          let label = $(LABEL)
           .data("r_i", r)
           .addClass("range_shown")
           .css(label_style)
          ;
          let range_start = res['ok']['ranges'][r]['v4r_start'];
          let range_stop = res['ok']['ranges'][r]['v4r_stop'];

          if(range_start === this_net) {
            if(range_stop === this_net_last_addr) {
              //label.html("&#x2550;"); // ═
              label.html("&#x25C6;"); // ◆
            } else if(range_stop < this_net_last_addr) {
              label.html("&#x25BC;"); // ▼
            } else { //range_stop > this_net_last_addr
              label.html("&#x2533;"); // ┳
            };
          } else if(range_start < this_net) {
            if(range_stop === this_net_last_addr) {
              label.html("&#x253B;"); // ┻
            } else if(range_stop < this_net_last_addr) {
              label.html("&#x251B;"); // ┛
            } else { //range_stop > this_net_last_addr
              label.html("&#x2503;"); // ┃
            };
          } else { //range_start > this_net
            if(range_stop === this_net_last_addr) {
              label.html("&#x25B2;"); // ▲
            } else if(range_stop < this_net_last_addr) {
              label.html("&#x25BA;"); // ►
            } else { //range_stop > this_net_last_addr
              label.html("&#x2513;"); // ┓
            };
          };

          label.appendTo(td);
        };
        td.appendTo(tr);
      };

      if(res['ok']['rows'][i]['subnets'] != undefined) {
        tr
         .append( $(SPAN).addClass("td")
           .text(res['ok']['rows'][i]['subnets']+" подсетей...")
           .title(res['ok']['rows'][i]['subnets_names']+"\n...")
         )
        ;
      } else {
        tr
         .append( $(SPAN).addClass("td")
           .append( vlan_label("net", "", res['ok']['rows'][i]['vlan_data'], false, "VLAN: ", "")
             .css({"margin-right": "0.2em"})
           )
           .append( $(SPAN)
             .text(res['ok']['rows'][i]['net_name'] === undefined?"":ellipsed(res['ok']['rows'][i]['net_name'], 60))
             .title(res['ok']['rows'][i]['net_name'] === undefined?"":res['ok']['rows'][i]['net_name'])
           )
         )
        ;
      };

      tr.appendTo(table);
    };

    table.appendTo(workarea);

    table.find(".range_shown")
     .on("click dblclick", function(e) {
       if ((e.type == "click" && e.ctrlKey) ||
           e.type == "dblclick"
       ) {
         e.stopPropagation();
         let r_i = $(this).data("r_i");
         let r_id = g_data['ranges'][r_i]['v4r_id'];
         if(r_id === undefined) {
           error_at();
           return;
         };

         edit_net_range("ext_v4net_range", r_id);
       };
     })
    ;
  });
};

function ip_row(ipdata) {
  let empty_colspan = net_cols_ids.length;
  let tr = $(TR).addClass("row")
   .data("ipdata", ipdata)
  ;

  let ip_td = $(TD).addClass("wsp")
  ;

  let ranges_span = $(SPAN)
   .css({"width": (g_range_bar_width+g_range_bar_margin)*g_data["net_ranges"].length, "display": "inline-block"})
  ;

  for(let i in g_data["net_ranges"]) {
    let r_label = $(LABEL).addClass("iprange");
    r_label.html('&#x200b;');
    r_label.css({"left": ((g_range_bar_width+g_range_bar_margin)*i)+"px",
                 "width": g_range_bar_width+"px",
                 "margin-right": g_range_bar_width+"px",
    });
    if(ipdata['ranges'][i]['in_range'] !== undefined) {
      r_label.addClass("iprange_shown");
      if(g_data["net_ranges"][i]['v4r_style'] != "{}") {
        try {
          let r_label_css = JSON.parse(g_data["net_ranges"][i]['v4r_style']);
          r_label.css(r_label_css);
        } catch(e) {
          r_label.css(g_default_range_style);

        };
      } else {
        r_label.css(g_default_range_style);
      };
      r_label.title(v4range_title(g_data["net_ranges"][i]));
      r_label.data("r_i", i);
    };
    ranges_span.append( r_label );
  };

  ip_td.append( ranges_span );

  let can_edit = false;
  if(ipdata['rights'] !== undefined &&
     (ipdata['rights'] & R_EDIT_IP_VLAN) > 0 &&
     ((ipdata['rights'] & R_DENYIP) == 0 ||
      (ipdata['rights'] & R_IGNORE_R_DENY) > 0
     )
  ) {
    can_edit = true;
  };


  if(ipdata['is_network'] !== undefined) {
    ip_td.append( $(SPAN).text(v4long2ip(ipdata['v4ip_addr'])) );
    ip_td.appendTo( tr );
    let empty_td = $(TD).prop("colspan", empty_colspan).addClass("empty_td")
     .text("Сеть")
    ;
    empty_td.appendTo( tr );
  } else if(ipdata['is_broadcast'] !== undefined) {
    ip_td.append( $(SPAN).text(v4long2ip(ipdata['v4ip_addr'])) );
    ip_td.appendTo( tr );
    let empty_td = $(TD).prop("colspan", empty_colspan).addClass("empty_td")
     .text("Broadcast")
    ;
    empty_td.appendTo( tr );
  } else if(ipdata['is_empty'] !== undefined) {
    ip_td.appendTo( tr );
    let empty_td = $(TD).prop("colspan", empty_colspan).addClass("empty_td");
    if(can_edit) {
      empty_td
       .append( $(SPAN).text("Занять: ") )
       .append( $(LABEL).text(v4long2ip(ipdata['start']))
         .addClass("button")
         .data("take_type", "ip")
         .data("ip", ipdata['start'])
         .click(function() { take_ip($(this)); })
       )
      ;
      if((ipdata['stop'] - ipdata['start']) > 1) {
        let next_ip = ipdata['start'] + 1;
        let next_ip_t = v4long2ip(next_ip);
        let last_ip_t = v4long2ip(ipdata['stop']);

        let val = "";
        let i=1;

        while(i < next_ip_t.length && i < last_ip_t.length) {
          if(next_ip_t.substring(0, i) == last_ip_t.substring(0, i)) {
            val = next_ip_t.substring(0, i);
            i++;
          } else {
            break;
          };
        };

        empty_td
         .append( $(SPAN).text(" - ") )
         .append( $(INPUT)
           .css({"width": "8em"})
           .addClass("any_ip")
           .val(val)
           .data("first", next_ip)
           .data("last", ipdata['stop']-1)
           .enterKey(function() { $(this).closest(".row").find(".take_any_btn").click(); })
         )
         .append( $(LABEL).text("+")
           .addClass("button")
           .addClass("take_any_btn")
           .data("take_type", "any_ip")
           .data("first", next_ip)
           .data("last", ipdata['stop']-1)
           .click(function() { take_ip($(this)); })
         )
        ;
      };
      if(ipdata['start'] !== ipdata['stop']) {
        empty_td
         .append( $(SPAN).text(" - ") )
         .append( $(LABEL).text(v4long2ip(ipdata['stop']))
           .addClass("button")
           .data("ip", ipdata['stop'])
           .data("take_type", "ip")
           .click(function() { take_ip($(this)); })
         )
        ;
      };
    } else {
      if(ipdata['start'] === ipdata['stop']) {
        empty_td
         .append( $(SPAN).text("Свободно: ") )
         .append( $(SPAN).text(v4long2ip(ipdata['start']))
         )
        ;
      } else {
        empty_td
         .append( $(SPAN).text("Свободно: ") )
         .append( $(SPAN).text(v4long2ip(ipdata['start']))
         )
         .append( $(SPAN).text(" - ") )
         .append( $(SPAN).text(v4long2ip(ipdata['stop']))
         )
        ;
      };
    };
    empty_td.appendTo( tr );
  } else {
    // menu
    ip_td
     .append( $(LABEL)
       .addClass("button")
       .addClass("ns")
       .addClass(["ui-icon", "ui-icon-bars"])
       .css({"float": "right", "clear": "none"})
       .click(function(e) {
         e.stopPropagation();
         ip_menu($(this));
       })
     )
    ;
    //
    ip_td.append( $(SPAN).text(v4long2ip(ipdata['v4ip_addr'])).addClass("ip_addr") );

    ip_td
     .append( vlan_label("ip", ipdata['v4ip_id'],  ipdata['vlan_data'], can_edit, "", "").addClass("ip_vlan") )
    ;

    ip_td
     .append( $(SPAN)
       .addClass("ns")
       .css({"display": "inline-block", "min-width": "2em"})
       //.html('&#x200b;')
     )
    ;

    ip_td.tooltip({
      classes: { "ui-tooltip": "ui-corner-all ui-widget-shadow wsp tooltip" },
      items: "SPAN.ip_addr",
      content: function() {
        if( $("UL").length > 0 ) return undefined;
        let row = $(this).closest(".row");
        let ipdata = row.data("ipdata");
        let lines=[];
        if(ipdata['ts'] > 0) {
          lines.push("Занят: "+from_unix_time(ipdata['ts'], false, 'н/д'));
          if(ipdata['fk_u_id'] !== null && g_data['aux_userinfo'][ipdata['fk_u_id']] != undefined) {
            let user_row = g_data['aux_userinfo'][ipdata['fk_u_id']];
            lines.push("\t"+user_row['u_name']+" ("+user_row['u_login']+")");
          };
        };
        let latest_ts=0;
        let latest_u=undefined;
        let latest_c_id=undefined;

        for(let i in ipdata['values']) {
          if(ipdata['values'][i]['ts'] !== undefined && ipdata['values'][i]['ts'] > latest_ts) {
            latest_ts = ipdata['values'][i]['ts'];
            latest_c_id = i;
            if(ipdata['values'][i]['u_id'] !== undefined) {
              latest_u = g_data['aux_userinfo'][ipdata['values'][i]['u_id']];
            };
          };
        };

        if(latest_ts > 0) {
          lines.push("Последнее изменение: "+from_unix_time(latest_ts, false, 'н/д'));
          lines.push("Поле: "+g_data['net_cols'][latest_c_id]['ic_name']);
          if(latest_u != undefined) {
            lines.push("\t"+latest_u['u_name']+" ("+latest_u['u_login']+")");
          };
        };
        return lines.join("\n");
      }
    });


    ip_td.appendTo( tr );
    for(let col_i in net_cols_ids) {
      let col_id = net_cols_ids[col_i];
      let td = $(TD)
       .addClass("unsaved_elm")
      ;
      td
       .append( ip_val_elm(ipdata, col_id, g_edit_all) )
      ;

      td.tooltip({
        classes: { "ui-tooltip": "ui-corner-all ui-widget-shadow wsp tooltip" },
        items: "TD",
        content: function() {
          if( $("UL").length > 0 ) return undefined;
          return $(this).find(".ip_value").data("title");
        }
      });

      td.appendTo( tr );
    };
  };

  if(can_edit) {
    tr
     .on("click dblclick", function(e) {
       if ((e.type == "click" && e.ctrlKey) ||
           e.type == "dblclick"
       ) {
         e.stopPropagation();
         let ipdata = $(this).data("ipdata");
         let td;
         if(e.target.nodeName == "TD") {
           td = $(e.target);
         } else {
           td = $(e.target).closest("TD");
         };
         if($(this).find(".ip_view").length > 0) {
           $(this).find(".ip_view").each(function() {
             $(this).replaceWith(ip_val_elm(ipdata, $(this).data('col_id'), true));
           });
           let focuson = td.find(".ip_edit");

           if(focuson.length > 0) {
             focuson.focus();
           };
         } else if($(this).find(".ip_edit").length > 0) {
           $(this).find(".ip_edit").each(function() {
             let changed = $(this).data("autosave_changed");
             if(changed) {
               g_autosave_changes--;
             };
             $(this).replaceWith(ip_val_elm(ipdata, $(this).data('col_id'), false));
           });

           if(g_autosave_changes < 0) {
             error_at();
             return;
           } else if(g_autosave_changes == 0) {
             $("#autosave_btn").css({"color": "gray"});
           } else {
             $("#autosave_btn").css({"color": "yellow"});
           };
         };
       };
     })
    ;
  };

  return tr;
};

function actionView4() {
  workarea.empty();
  fixed_div.empty();
  let net = getUrlParameter("net", undefined);
  let masklen = getUrlParameter("masklen", undefined);

  let is_new = getUrlParameter("is_new", false);

  if(net === undefined || ! String(net).match(/^\d+$/) || Number(net) > 4294967295) { error_at(); return; };
  if(masklen === undefined || ! String(masklen).match(/^\d{1,2}$/) || Number(masklen) > 32) { error_at(); return; };

  if(Number(net) != ip4net(net, masklen)) {
    error_at();
    return;
  };

  run_query({"action": "view_v4", "net": net, "masklen": masklen}, function(res) {

    if(res['ok']['gone'] !== undefined) {
      window.location = "?action=nav_v4net&net="+net+"&masklen="+masklen+(usedonly?"&usedonly":"")+(DEBUG?"&debug":"");
      return;
    };

    g_data = res['ok'];

    let backlen = 0;
    if(masklen <=8 ) {
      backlen = 0;
    } else if(masklen <= 16) {
      backlen = 8;
    } else if(masklen <= 24) {
      backlen = 16;
    } else {
      backlen = 24;
    };

    let back_net = ip4net(net, backlen);

    document.title = "IPDB: "+v4long2ip(net)+"/"+masklen+" "+res['ok']['net_name'];

    fixed_div
     .append( $(DIV)
       .append( $(A)
         .prop("href", "?action=nav_v4&net="+ip4net(net, backlen)+"&masklen="+backlen+(usedonly?"&usedonly":"")+(DEBUG?"&debug":""))
         .text("<<<")
         .title( "Назад к сети: "+net_mask_wc(net, backlen) )
       )
       .append( $(SPAN).addClass("min1em") )
       .append( $(SPAN).text( net_mask_wc(net, masklen) ) )
       .append( $(SPAN).addClass("min1em") )
       .append( $(LABEL).text("В избранном: ") )
       .append( $(INPUT).prop({"type": "checkbox", "checked": res['ok']['fav'] == 1})
         .on("change", function() {
           let checked = $(this).is(":checked");
           run_query({"action": "fav_v4", "net": net, "masklen": masklen, "fav": checked?1:0}, function(res) {
           });
         })
       )
     )
     .append( $(DIV)
       .css({"display": "flex", "align-items": "center"})
       .append( $(LABEL).addClass(["ui-icon", "ui-icon-info", "button"])
         .css({"margin-left": "0.5em"})
         .click(function() {
           g_show_net_info = !g_show_net_info;
           $("#net_info").toggle(g_show_net_info);
           save_local("show_net_info", g_show_net_info);
         })
       )
       .append( $(SPAN).addClass("min1em") )
       .append( (g_data['net_rights'] & R_MANAGE_NET) == 0?$(LABEL):$(LABEL)
         .addClass(["ui-icon", "ui-icon-edit"])
         .title("Редактировать. Можно также сделать CTRL-Click или Dbl-Click на поле")
         .click(function() {
           let elm = $("#net_name_editable");
           if(elm.hasClass("editable_edit")) {
             $(this).title("Редактировать. Можно также сделать CTRL-Click или Dbl-Click на поле")
           } else {
             $(this).title("Отменить редактирование. Также можно нажать ESC когда курсор в поле ввода");
           };
           elm.trigger("editable_toggle");
         })
       )
       .append( $(SPAN)
         .css({"font-size": "xx-large"})
         .append(
           editable_elm({
             'object': 'net',
             'prop': 'v4net_name',
             'id': String(g_data['net_id']),
             '_edit_css': { 'width': '50em' },
             '_elm_id': 'net_name_editable',
             '_after_save': function(elm, new_val) {
               g_data['net_name'] = new_val;
               $("#net_changed_ts").text( from_unix_time( unix_timestamp() ) );
               $("#net_changed_user").text(userinfo['name'] +" ("+userinfo['login']+")"); 
             }
           }, is_new && (g_data['net_rights'] & R_MANAGE_NET) > 0)
         )
       )
       .append( $(SPAN).addClass("min1em") )
       .append( vlan_label("net", g_data['net_id'], g_data['vlan_data'], (g_data['net_rights'] & R_MANAGE_NET) > 0, "VLAN: ", "VLAN: не задан")
         .addClass("net_vlan")
       )
     )
    ;

    g_show_net_info = get_local("show_net_info", g_show_net_info);

    var info_div = $(DIV)
     .prop("id", "net_info")
    ;

    fixed_div
     .append( info_div.toggle(g_show_net_info) )
    ;

    if((g_data['net_rights'] & R_VIEW_NET_INFO) > 0) {

      info_div
       .append( $(DIV)
         .append( $(SPAN).text("Занята: ") )
         .append( $(SPAN).text(from_unix_time(res['ok']['taken_ts'], false, 'н.д.') ) )
         .append( res['ok']['taken_u_id'] === null?$(SPAN):$(SPAN).text(" Пользователем: ") )
         .append( res['ok']['taken_u_id'] === null?$(SPAN):$(SPAN)
           .text(g_data['aux_userinfo'][ res['ok']['taken_u_id'] ]['u_name']+" ("+
                 g_data['aux_userinfo'][ res['ok']['taken_u_id'] ]['u_login']+")"
           )
         )
         .append( $(SPAN).addClass("min1em") )
         .append( (g_data['net_rights'] & R_MANAGE_NET) == 0?$(LABEL):$(LABEL)
           .addClass(["button", "ui-icon", "ui-icon-trash"])
           .title("Удалить сеть")
           .data("back_net", back_net)
           .data("backlen", backlen)
           .click(function() {
             let back_net = $(this).data("back_net");
             let backlen = $(this).data("backlen");
             show_confirm_checkbox("Подтвердите удаление сети.\nВнимание: отменить операцию будет невозможно!", function() {
               run_query({"action": "del_net", "v": "4", "net_id": String(g_data['net_id'])}, function(res) {
                 g_autosave_changes = 0;
                 window.location = "?action=nav_v4&net="+back_net+"&masklen="+backlen+
                                   (usedonly?"&usedonly":"")+(DEBUG?"&debug":"");

               });
             });
           })
         )
       )
      ;

      if(res['ok']['ts'] > 0 && res['ok']['fk_u_id'] !== null &&
         res['ok']['fk_u_id'] !== undefined && g_data['aux_userinfo'][ res['ok']['fk_u_id'] ] != undefined
      ) {
        info_div
         .append( $(DIV)
           .append( $(SPAN).text("Изменена: ") )
           .append( $(SPAN).text(from_unix_time(res['ok']['ts']) )
             .prop("id", "net_changed_ts")
           )
           .append( $(SPAN).text(" Пользователем: ") )
           .append( $(SPAN)
             .text(g_data['aux_userinfo'][ res['ok']['fk_u_id'] ]['u_name']+" ("+
                   g_data['aux_userinfo'][ res['ok']['fk_u_id'] ]['u_login']+")"
             )
             .prop("id", "net_changed_user")
           )
         )
        ;
      };

      info_div
       .append( $(DIV)
         .append( (g_data['net_rights'] & R_MANAGE_NET) == 0?$(LABEL):$(LABEL)
           .addClass(["ui-icon", "ui-icon-edit"])
           .css({"vertical-align": "top"})
           .title("Редактировать. Можно также сделать CTRL-Click или Dbl-Click на поле")
           .click(function() {
             let elm = $("#net_descr_editable");
             if(elm.hasClass("editable_edit")) {
               $(this).title("Редактировать. Можно также сделать CTRL-Click или Dbl-Click на поле")
             } else {
               $(this).title("Отменить редактирование. Также можно нажать ESC когда курсор в поле ввода");
             };
             elm.trigger("editable_toggle");
           })
         )
         .append(
           editable_elm({
             'object': 'net',
             'prop': 'v4net_descr',
             'id': String(g_data['net_id']),
             '_view_classes': ["wsp"],
             '_view_css': {"display": "inline-block", "border": "2px inset gray", "padding": "2px"},
             '_edit_css': { 'width': '50em', 'min-height': '20em' },
             '_elm_id': 'net_descr_editable',
             '_after_save': function(elm, new_val) {
               g_data['net_descr'] = new_val;
               $("#net_changed_ts").text( from_unix_time( unix_timestamp() ) );
               $("#net_changed_user").text(userinfo['name'] +" ("+userinfo['login']+")"); 
             }
           }, false)
         )
       )
      ;

      info_div
       .append( $(DIV)
         .append( $(SPAN).text("Владелец: ") )
         .append( editable_elm({
             "object": "net",
             "prop": "v4net_owner",
             'id': String(g_data['net_id']),
             '_elm_id': 'net_owner_editable',
             '_after_save': function(elm, new_val) {
               g_data['net_owner'] = new_val;
               $("#net_changed_ts").text( from_unix_time( unix_timestamp() ) );
               $("#net_changed_user").text(userinfo['name'] +" ("+userinfo['login']+")"); 
             }
           })
         )

         .append( (g_data['net_rights'] & R_MANAGE_NET) == 0?$(LABEL):$(LABEL)
           .addClass(["ui-icon", "ui-icon-edit"])
           .click(function() {
             $("#net_owner_editable").trigger("editable_toggle");
           })
         )
         .append( $(SPAN).addClass("min1em") )
         .append( (g_data['net_rights'] & R_MANAGE_NET) == 0?$(LABEL):$(LABEL)
           .addClass("button")
           .addClass("set_vlan_btn")
           .text("Задать VLAN")
           .click(function() {
             $(".vlan.net_vlan").trigger("set");
           })
         )
       )
      ;
    };

    let current_net_rights_span = $(SPAN);

    for(let k in r_keys) {
      let right = r_keys[k];
      let found = false;
      for(let i in g_rights[right]['used_in']) {
        if(g_rights[right]['used_in'][i] == "ext_v4net_range" ||
           g_rights[right]['used_in'][i] == "v4net_acl"
        ) {
          found = true;
          break;
        };
      };

      let is_set = (g_data['net_rights'] & right) > 0;
      if(is_set && found) {
        current_net_rights_span
         .append( $(SPAN).addClass("right_on")
           .text(g_rights[right]['label'])
           .title(g_rights[right]['descr'])
         )
        ;
      };
    };

    info_div
     .append( $(DIV)
       .append( $(SPAN).text("Ваши права на сеть: ") )
       .append( current_net_rights_span )
       .append( (g_data['net_rights'] & R_VIEW_NET_INFO) == 0?$(LABEL):$(LABEL)
         .text("Права групп")
         .addClass("button")
         .click(function() {
           if(g_autosave_changes > 0) {
             show_dialog("На странице есть несохраненные поля.\nСперва сохраните изменения.");
             return;
           };
           edit_rights("v4net_acl", g_data['net_id'], (g_data['net_rights'] & R_MANAGE_NET) > 0,  function() {
             window.location = "?action=view_v4&net="+g_data['net_addr']+"&masklen="+g_data['net_masklen']+
                               (usedonly?"&usedonly":"")+(DEBUG?"&debug":"");
             return;
           });
         })
       )
     )
    ;

    if((g_data['net_rights'] & R_VIEW_NET_INFO) > 0) {
      let net_ranges_span = $(SPAN);

      for(let i in g_data['net_in_ranges']) {
        let range = g_data['net_in_ranges'][i];
        let range_icon_css = {};
        try {
          range_icon_css = JSON.parse(range['v4r_icon_style']);
        } catch(e) {
          range_icon_css = {};
        };
        let range_icon = g_default_range_icon;
        if(range['v4r_icon'] !== "") {
          range_icon = range['v4r_icon'];
        };
        net_ranges_span
         .append( $(SPAN).addClass("range_span")
           .title( v4range_title(range) )
           .append( $(LABEL).addClass(["ui-icon", range_icon]).css(range_icon_css) )
           .append( $(SPAN).text(range['v4r_name']) )
         )
        ;
      };

      info_div
       .append( $(DIV)
         .append( $(SPAN).text("Сеть входит в диапазоны: ") )
         .append( net_ranges_span )
       )
      ;

    };

    if(res['ok']['ips'] !== undefined) {

      g_edit_all = get_local("edit_all", g_edit_all);

      fixed_div
       .append( $(DIV)
         .append( $(SPAN)
           .append( $(LABEL)
             .text("Редактировать все: ")
             .prop("for", "edit_all")
           )
           .append( $(INPUT)
             .prop({"id": "edit_all", "type": "checkbox", "checked": g_edit_all})
             .on("change", function() {
               let state = $(this).is(":checked");
               save_local("edit_all", state);


               $(".main_table").find("TBODY").find("TR").each(function() {
                 let row = $(this);
                 let row_ipdata = row.data("ipdata");
                 if(row_ipdata['is_taken'] !== undefined) {
                   row.find(".ip_value").each(function() {
                     let col_id = $(this).data("col_id");
                     let changed = $(this).data("autosave_changed");
                     if(changed === undefined || changed === false) {
                       let new_elm = ip_val_elm(row_ipdata, col_id, state);
                       $(this).replaceWith(new_elm);
                     };
                   });
                 };
               });
             })
           )
         )
       )
      ;

      let table = $(TABLE).addClass("main_table")
      ;

      let thead = $(TR)
      ;

      thead
       .append( $(TH)
         .text("IP")
         .append( (g_data['net_rights'] & R_MANAGE_NET) == 0?$(LABEL):$(LABEL)
           .addClass(["button", "ui-icon", "ui-icon-plus"])
           .title("Добавить диапазон")
           .css({"float": "left"})
           .click(function() {
             if(g_autosave_changes > 0) {
               show_dialog("На странице есть несохраненные поля.\nСперва сохраните изменения.");
               return;
             };
             edit_net_range("int_v4net_range", undefined);
           })
         )
         .append( (g_data['net_rights'] & R_MANAGE_NET) == 0?$(LABEL):$(LABEL)
           .addClass(["button", "ui-icon", "ui-icon-bullets"])
           .title("Назначение полей")
           .css({"float": "right"})
           .click(function() {
             if(g_autosave_changes > 0) {
               show_dialog("На странице есть несохраненные поля.\nСперва сохраните изменения.");
               return;
             };
             net_cols_edit();
           })
         )
       )
      ;

      net_cols_ids = keys(res['ok']['net_cols']);
      net_cols_ids.sort(function(a, b) {
        return Number(res['ok']['net_cols'][a]['ic_sort']) - Number(res['ok']['net_cols'][b]['ic_sort']);
      });

      for(let col_i in net_cols_ids) {
        let col_id = net_cols_ids[col_i];
        let th = $(TH)
         .text(res['ok']['net_cols'][col_id]['ic_name'])
        ;
        if(res['ok']['net_cols'][col_id]['ic_icon'] != '') {
          let icon_css;
          try {
            icon_css = JSON.parse(res['ok']['net_cols'][col_id]['ic_icon_style']);
          } catch(e) {
            ison_css = {};
          };
          th
           .append( $(LABEL)
             .addClass("ui-icon")
             .addClass(res['ok']['net_cols'][col_id]['ic_icon'])
             .css(icon_css)
           )
          ;
        };
        th.appendTo(thead);
      };

      table
       .append( $(THEAD)
         .append( thead )
       )
      ;

      let tbody = $(TBODY);


      for(let ip_i in res['ok']['ips']) {
        let ipdata = res['ok']['ips'][ip_i];
        let tr = ip_row(ipdata);
        tr.appendTo( tbody );

      };

      table.append( tbody );
      table.appendTo( workarea );

      table.tooltip({
        classes: { "ui-tooltip": "ui-corner-all ui-widget-shadow wsp tooltip" },
        items: ".iprange",
        content: function() {
          let r_i = $(this).data("r_i");
          if(r_i === undefined) return;
          return v4range_title(g_data['net_ranges'][r_i]);
        }
      });

      if((g_data['net_rights'] & R_MANAGE_NET) > 0) {
        table.find(".iprange_shown").on("click dblclick", function(e) {
          if ((e.type == "click" && e.ctrlKey) ||
              e.type == "dblclick"
          ) {
            e.stopPropagation();
            let r_i = $(this).data("r_i");
            if(r_i === undefined) return;
            if(g_autosave_changes > 0) {
              show_dialog("На странице есть несохраненные поля.\nСперва сохраните изменения.");
              return;
            };
            edit_net_range("int_v4net_range", g_data['net_ranges'][r_i]['v4r_id']);
          };
        });
      };
        
    } else {
      fixed_div
       .append( $(DIV).text("У вас нет прав просмотра IP адресов этой сети") )
      ;
    };

    if(is_new && (g_data['net_rights'] & R_MANAGE_NET) > 0) {
      $("#net_name_editable").focus();
      history.pushState(undefined, undefined,
                        "?action=view_v4&net="+net+"&masklen="+masklen+(usedonly?"&usedonly":"")+(DEBUG?"&debug":"")
      );
    };
  });
};

function take_ip(elm) {
  let row = elm.closest(".row");
  let prev_ipdata = row.data("ipdata");
  let take_type = elm.data("take_type");
  if(take_type == undefined) { error_at(); return; };
  if(prev_ipdata == undefined) { error_at(); return; };

  let take_ip = undefined;
  if(take_type === "ip") {
    take_ip = elm.data("ip");
  } else if(take_type === "any_ip") {
    let v = row.find(".any_ip").val();
    take_ip = v4ip2long(v);
    if(take_ip === false) {
      row.find(".any_ip").animateHighlight("red", 500);
      return;
    };
    let first = elm.data("first");
    let last = elm.data("last");
    if(take_ip < first || take_ip > last) {
      row.find(".any_ip").animateHighlight("red", 500);
      return;
    };
  } else {
    error_at(); return;
  };

  if(take_ip === undefined) { error_at(); return; };

  run_query({"action": "take_ip4", "take_ip": String((take_ip >>> 0)), "ranges_orig": g_data['ranges_orig']}, function(res) {

    if(res['ok']['taken'] !== undefined) {
      show_dialog("Адрес уже кем-то занят, обновите страницу!");
      return;
    };

    if(res['ok']['gone'] !== undefined) {
      show_dialog("Сеть не существует. Возможно кто-то ее уже удалил, обновите страницу!");
      return;
    };

    if(res['ok']['ranges_changed'] !== undefined) {
      show_dialog("Кто-то внес изменения в диапазоны сети, обновите страницу!");
      return;
    };

    let new_ipdata = res['ok']['ipdata'];
    let new_ip_row = ip_row(new_ipdata);
    row.replaceWith( new_ip_row );

    let prev_start = prev_ipdata['start'];
    let prev_stop = prev_ipdata['stop'];

    if(prev_start != prev_stop) {
      if(take_ip > prev_start) {
        let before_data = dup(prev_ipdata);
        before_data['stop'] = take_ip - 1;
        let before_row = ip_row(before_data);
        before_row.insertBefore(new_ip_row);
      };
      if(take_ip < prev_stop) {
        let after_data = dup(prev_ipdata);
        after_data['start'] = take_ip + 1;
        let after_row = ip_row(after_data);
        after_row.insertAfter(new_ip_row);
      };
    };
  });
};

function ip_menu(elm) {
  $("UL.popupmenu").remove();
  let row = elm.closest(".row");
  let ipdata = row.data("ipdata");
  
  let menu = $(UL)
   .addClass("popupmenu")
   .css({"background-color": "white", "border": "1px solid black", "display": "inline-block", "z-index": 100})
   .css({"padding": "0.2em"})
   .css({"position": "absolute"})
   .append( $(LI)
     .title("Закрыть меню")
     .append( $(DIV)
       //.css({"display": "inline-block"})
       .append( $(LABEL).addClass(["ui-icon", "ui-icon-arrowreturn-1-w"]) )
       .append( $(SPAN).html("&#x200b;") )
       .click(function(e) {
         e.stopPropagation();
         $("UL.popupmenu").remove();
       })
     )
   )
   .append( $(LI)
     .append( $(DIV).text("Ссылки") )
     .append( $(UL)
       .append( $(LI)
         .append( $(DIV)
           .append( $(A)
             .prop({"target": "_blank", "href": "http://"+v4long2ip(ipdata['v4ip_addr'])+"/"})
             .text("HTTP")
           )
         )
       )
       .append( $(LI)
         .append( $(DIV)
           .append( $(A)
             .prop({"target": "_blank", "href": "https://"+v4long2ip(ipdata['v4ip_addr'])+"/"})
             .text("HTTPS")
           )
         )
       )
       .append( $(LI)
         .append( $(DIV)
           .append( $(A)
             .prop({"target": "_blank", "href": "ssh://"+v4long2ip(ipdata['v4ip_addr'])})
             .text("SSH")
           )
         )
       )
     )
   )
  ;


  if((ipdata['rights'] & R_EDIT_IP_VLAN) != 0 &&
     ((ipdata['rights'] & R_DENYIP) == 0 ||
      (ipdata['rights'] & R_IGNORE_R_DENY) != 0
     )
  ) {

    if(row.find(".ip_view").length > 0) {
      menu
       .append( $(LI)
         .append( $(DIV)
           .title("Также можно сделать CTRL-Click или dbl-Click на строке...")
           .append( $(LABEL).addClass(["ui-icon", "ui-icon-edit"]) )
           .append( $(SPAN).html("Редактировать&#x20F0;") )
           .click(function(e) {
             e.stopPropagation();

             let row = $(this).closest("TR");

             row.find(".ip_view").each(function() {
               $(this).replaceWith(ip_val_elm(ipdata, $(this).data('col_id'), true));
             });
             $("UL.popupmenu").remove();

             row.find(".ip_edit").first().focus();
           })
         )
       )
      ;
    };

    if(row.find(".ip_edit").length > 0) {
      menu
       .append( $(LI)
         .append( $(DIV)
           //.css({"display": "inline-block"})
           .append( $(LABEL).addClass(["ui-icon", "ui-icon-undo"]) )
           .append( $(SPAN).text("Перестать редактировать") )
           .click(function(e) {
             e.stopPropagation();

             let row = $(this).closest("TR");

             row.find(".ip_edit").each(function() {
               let changed = $(this).data("autosave_changed");
               if(changed) {
                 g_autosave_changes--;
               };
               $(this).replaceWith(ip_val_elm(ipdata, $(this).data('col_id'), false));
             });
             if(g_autosave_changes < 0) {
               error_at();
               return;
             } else if(g_autosave_changes == 0) {
               $("#autosave_btn").css({"color": "gray"});
             } else {
               $("#autosave_btn").css({"color": "yellow"});
             };
             $("UL.popupmenu").remove();
           })
         )
       )
      ;
    };

    menu
     .append( $(LI)
       .append( $(DIV)
         //.css({"display": "inline-block"})
         .append( $(LABEL).addClass(["ui-icon", "ui-icon-trash"]) )
         .append( $(SPAN).text("Освободить") )
         .click(function(e) {
           e.stopPropagation();
           let row = $(this).closest("TR");
           let ipdata = row.data("ipdata");
           if(ipdata === undefined) { error_at(); return; };
           show_confirm("Подтвердите освобождение адреса "+v4long2ip(ipdata['v4ip_addr'])+
                        "\nВнимание: все данные по этому адресу будут удалены.\nОтмена будет невозможна", function() {
             let ip_id = ipdata['v4ip_id'];
             run_query({"action": "free_ip", "v": "4", "id": String(ip_id)}, function(res) {

               row.find(".ip_edit").each(function() {
                 let changed = $(this).data("autosave_changed");
                 if(changed) {
                   g_autosave_changes--;
                 };
               });
               if(g_autosave_changes < 0) {
                 error_at();
                 return;
               } else if(g_autosave_changes == 0) {
                 $("#autosave_btn").css({"color": "gray"});
               } else {
                 $("#autosave_btn").css({"color": "yellow"});
               };

               $("UL.popupmenu").remove();
               let new_ip_data = {};
               new_ip_data['ranges'] = ipdata['ranges'];
               new_ip_data['rights'] = ipdata['rights'];
               new_ip_data['is_empty'] = 1;
               new_ip_data['start'] = ipdata['v4ip_addr'];
               new_ip_data['stop'] = ipdata['v4ip_addr'];

               row.replaceWith( ip_row(new_ip_data) );
             });
           });
         })
       )
     )
    ;

    menu
     .append( $(LI)
       .append( $(DIV)
         //.css({"display": "inline-block"})
         .append( $(LABEL).addClass(["ui-icon", "ui-icon-sitemap"]) )
         .append( $(SPAN).text("Задать VLAN") )
         .click(function(e) {
           e.stopPropagation();
           let row = $(this).closest("TR");
           $("UL.popupmenu").remove();
           row.find(".ip_vlan").trigger("set");
         })
       )
     )
    ;
  };

  //let elm_offset = elm.offset();
  //let elm_width = elm.width();

  let td_width = elm.closest("TD").width();

  menu.css({"top": "0px", "left": td_width+10+"px"});

  menu.appendTo(elm.closest("TD"));

  menu.menu();

  menu.on("click dblclick", function(e) { e.stopPropagation(); });

  $(".tooltip").remove();
};

function vlan_val_elm(row_data, prop, state) {
  let ret;

  let can_edit = false;
  if(row_data['rights'] !== undefined &&
     (row_data['rights'] & R_EDIT_IP_VLAN) > 0 &&
     ((row_data['rights'] & R_DENYIP) == 0 ||
      (row_data['rights'] & R_IGNORE_R_DENY) > 0
     )
  ) {
    can_edit = true;
  };

  let value = row_data[prop];

  if(state && can_edit) {
    if(prop == "vlan_descr") {
      ret = $(TEXTAREA);
      ret.css({"min-height": "1em", "min-width": "80em"});
      let lines = String(value).split("\n").length;
      ret.css({"height": lines+"em"});
    } else {
      ret = $(INPUT);
    };
    ret.val(value);

    ret.saveable({"object": "vlan_value", "id": String(row_data['vlan_id']), "prop": prop});
    ret.addClass("vlan_edit");

    ret.keyup(function(e) {
      if(e.key === "Escape") {
        e.stopPropagation();
        let row = $(this).closest(".row");
        row.find(".vlan_edit").each(function() {
          if(!$(this).data("autosave_changed")) {
            $(this).replaceWith( vlan_val_elm(row.data("row_data"), $(this).data("prop"), false ));
          };
        });
      };

    });

  } else {
    ret = $(SPAN)
     .addClass("wsp")
     .addClass("vlan_view")
     .text(value)
    ;
  };

  let css = {};
  ret.addClass("vlan_value");
  ret.data("prop", prop);
  ret.css(css);

  return ret;
};

function ip_val_elm(ipdata, col_id, state) {
  let ret;
  let coldata = g_data['net_cols'][col_id];

  let can_edit = false;
  if(ipdata['rights'] !== undefined &&
     (ipdata['rights'] & R_EDIT_IP_VLAN) > 0 &&
     ((ipdata['rights'] & R_DENYIP) == 0 ||
      (ipdata['rights'] & R_IGNORE_R_DENY) > 0
     )
  ) {
    can_edit = true;
  };

  let value = "";
  let ts = undefined;
  let u_id = undefined;

  if(ipdata["values"][col_id] !== undefined) {
    value = ipdata["values"][col_id]['v'];
    ts = ipdata["values"][col_id]['ts'];
    u_id = ipdata["values"][col_id]['u_id'];
  };

  let title = "";
  if(ts !== undefined) {
    title = "Изменен: "+from_unix_time(ts);
    if(u_id !== undefined && g_data['aux_userinfo'][u_id] !== undefined) {
      title += "\n"+g_data['aux_userinfo'][u_id]['u_name']+" ("+g_data['aux_userinfo'][u_id]['u_login']+")";
    };
  };

  let style = "{}";

  if(state && can_edit) {
    style = coldata['ic_style'];
    if(coldata['ic_type'] == "textarea") {
      ret = $(TEXTAREA);
      ret.css({"min-height": "1em"});
      let lines = String(value).split("\n").length;
      ret.css({"height": lines+"em"});
    } else {
      ret = $(INPUT);
    };
    ret.val(value);

    ret.saveable({"object": "ip_value", "id": String(ipdata['v4ip_id']), "col_id": col_id});
    ret.addClass("ip_edit");

    ret.keyup(function(e) {
      if(e.key === "Escape") {
        e.stopPropagation();
        let row = $(this).closest(".row");
        row.find(".ip_edit").each(function() {
          if(!$(this).data("autosave_changed")) {
            $(this).replaceWith( ip_val_elm(row.data("ipdata"), $(this).data("col_id"), false ));
          };
        });
      };

    });

  } else {
    style = coldata['ic_view_style'];
    ret = $(SPAN)
     .addClass("wsp")
     .addClass("ip_view")
     .text(value)
    ;
  };

  let css = {};

  try {
    css = JSON.parse(style);
  } catch(e) {
    css = {};
  };
  ret.addClass("ip_value");
  ret.data("col_id", col_id);
  ret.css(css);
  ret.data("title", title);

  return ret;
};

function editable_elm(data, edit) {
  let ret;
  let value = "";

  if(data['object'] == 'net' && data['prop'] == 'v4net_descr') {
    value = g_data[ 'net_descr' ];
  } else if(data['object'] == 'net' && data['prop'] == 'v4net_name') {
    value = g_data[ 'net_name' ];
  } else if(data['object'] == 'net' && data['prop'] == 'v4net_owner') {
    value = g_data[ 'net_owner' ];
  } else if(data['object'] == 'vdom' && data['prop'] == 'vd_name') {
    value = g_data[ 'vd_name' ];
  } else if(data['object'] == 'vdom' && data['prop'] == 'vd_descr') {
    value = g_data[ 'vd_descr' ];
  } else {
    error_at("Unknown object: "+data['object']+" prop: "+data['prop']);
    return;
  };
  if(edit) {
    if(data['object'] == 'net' && data['prop'] == 'v4net_descr') {
      ret = $(TEXTAREA);
    } else if(data['object'] == 'vdom' && data['prop'] == 'vd_descr') {
      ret = $(TEXTAREA);
    } else if(data['object'] == 'net' && data['prop'] == 'v4net_owner') {
      ret = $(SELECT);
      ret.append( $(OPTION).text("не задан").val(0) );
      run_query({"action": "users_list"}, function(res) {

        for(let i in res['ok']['users_list']) {
          let u_id = res['ok']['users_list'][i]['u_id'];
          if(g_data['aux_userinfo'][u_id] === undefined) {
            g_data['aux_userinfo'][u_id] = res['ok']['users_list'][i];
          };
          ret.append( $(OPTION).val(u_id).text(res['ok']['users_list'][i]['u_name']+" ("+res['ok']['users_list'][i]['u_login']+")") );
        };

        ret.val(value);
        ret.on("select change", function() { $(this).trigger("input_stop"); });
      });
    } else {
      ret = $(INPUT).css("font-size", "inherit");
    };
    ret.addClass("editable_edit");
    ret.val(value);
    ret.saveable(data);
    ret.keyup(function(e) {
      if(e.key === "Escape") {
        e.stopPropagation();
        if($(this).data("autosave_changed")) {
          g_autosave_changes--;
          if(g_autosave_changes < 0) {
            error_at();
            return;
          } else if(g_autosave_changes == 0) {
            $("#autosave_btn").css({"color": "gray"});
          };
        };
        $(this).replaceWith( editable_elm( $(this).data("autosave_data"), false ) );
      };
    });
    if(data['_edit_css'] !== undefined) {
      ret.css(data['_edit_css']);
    };
    if(data['_edit_classes'] !== undefined) {
      ret.addClass(data['_edit_classes']);
    };
  } else {
    ret = $(SPAN);
    ret.addClass("editable_view");
    if(data['object'] == 'net' && data['prop'] == 'v4net_owner') {
      if(value == 0) {
        ret.text("не задан");
      } else if(g_data['aux_userinfo'][value] !== undefined) {
        ret.text(g_data['aux_userinfo'][value]['u_name']+" ("+
                 g_data['aux_userinfo'][value]['u_login']+")"
        );
      } else {
        ret.text("нет данных");
      };
    } else {
      ret.text(value);
    };
    if(data['_view_css'] !== undefined) {
      ret.css(data['_view_css']);
    };
    if(data['_view_classes'] !== undefined) {
      ret.addClass(data['_view_classes']);
    };
    ret
     .on("click dblclick", function(e) {
       if ((e.type == "click" && e.ctrlKey) ||
           e.type == "dblclick"
       ) {
         $(this).trigger("editable_toggle");
       };
     })
    ;
  };
  ret.data("editable_data", data);
  ret.on("editable_toggle", function() {
    let data = $(this).data("editable_data");
    if(data['object'] == 'net') {
      if( (g_data['net_rights'] & R_MANAGE_NET) == 0 ) return;
    } else if(data['object'] == 'vdom') {
      if(!userinfo['is_admin']) return;
    };
    let new_state = $(this).hasClass("editable_view");
    if(!new_state && $(this).data("autosave_changed") === true) {
      g_autosave_changes--;
      if(g_autosave_changes < 0) {
        error_at();
        return;
      } else if(g_autosave_changes == 0) {
        $("#autosave_btn").css({"color": "gray"});
      } else {
        $("#autosave_btn").css({"color": "yellow"});
      };
    };
    let new_elm = editable_elm(data, new_state);
    $(this).replaceWith( new_elm );
    if(new_state) new_elm.focus();
  });
  if(data['_elm_id'] !== undefined) {
    ret.prop('id', data['_elm_id']);
  };
  return ret;
};

function edit_rights(object, object_id, allow_edit, on_done) {
  run_query({'action': 'get_rights', 'object': object, 'object_id': String(object_id)}, function(res) {

    let dialog = $(DIV).addClass("dialog_start")
     .data('object', object)
     .data('object_id', object_id)
     .data('on_done', on_done)
     .data('groups', res['ok']['groups'])
    ;

    switch(object) {
    case "v4net_acl":
      dialog.title("Права доступа к сети: "+v4long2ip(g_data['net_addr'])+"/"+g_data['net_masklen']+" "+
                   g_data['net_name']
      );
      break;
    default:
      error_at("Object:"+object+" is not implemented");
    };

    let table = $(DIV).addClass("table")
     .appendTo(dialog)
    ;

    let change_check = "";

    let not_in_list = [];

    let k_a = keys(res['ok']['groups']);
    sort_by_string_key(k_a, res['ok']['groups'], 'g_name');

    for(let i in k_a) {
      let g_id = k_a[i];
      if(res['ok']['groups'][g_id]['rights'] == 0) {
        not_in_list.push(g_id);
        continue;
      };
      change_check += g_id+":"+res['ok']['groups'][g_id]['rights']+";";
      table.append( rights_row(object, object_id, res['ok']['groups'][g_id], allow_edit) );
    };

    dialog.data("change_check", change_check);

    if(allow_edit) {
      let last_row = $(DIV).addClass("tr");

      let select = $(SELECT)
       .append( $(OPTION).text("Выберете группу...").val(0) )
       .val(0)
       .tooltip({
         classes: { "ui-tooltip": "ui-corner-all ui-widget-shadow wsp tooltip" },
         items: "SELECT",
         content: function() {
           return $(this).find("OPTION:selected").prop("title");
         }
       })
      ;

      for(let i in not_in_list) {
        let g_id = not_in_list[i];
        select
         .append( $(OPTION)
           .text(res['ok']['groups'][g_id]['g_name'])
           .title(res['ok']['groups'][g_id]['g_descr'])
           .val(g_id)
         )
        ;
      };

      last_row
       .append( $(SPAN).addClass("td")
         .append( select )
       )
      ;

      last_row
       .append( rights_tds(object, 0, true) )
      ;

      last_row
       .append( $(SPAN).addClass("td")
         .append( $(LABEL).addClass(["button", "ui-icon", "ui-icon-plus"])
           .click(function() {
             let dialog = $(this).closest(".dialog_start");
             let select = dialog.find("SELECT");
             let option = select.find(":selected");
             let tr = $(this).closest(".tr");
             let g_id = select.val();
             if(g_id == 0) return;

             let this_rights = 0;

             tr.find(".right").each(function() {
               if( $(this).hasClass("right_on") ) {
                 this_rights = this_rights | $(this).data("right");
               };
             });

             if(this_rights == 0) return;

             let new_g_data = dialog.data("groups")[g_id];
             new_g_data['_new'] = true;
             new_g_data['rights'] = this_rights;
             let new_row = rights_row(dialog.data("object"), dialog.data("object_id"),
               new_g_data, true
             );
             new_row.insertBefore(tr);
             option.remove();
           })
         )
       )
      ;

      table.append( last_row );
    };

    let buttons = [];

    if(allow_edit) {
      buttons.push({
        'text': 'Сохранить',
        'click': function() {
          let dlg = $(this);

          let rights = {};

          dlg.find(".rights_row").each(function() {
            let this_rights = 0;
            $(this).find(".right").each(function() {
              if($(this).hasClass("right_on")) {
                let right = $(this).data("right");
                this_rights |= right;
              };
            });
            if(this_rights > 0) {
              let group = $(this).data("group");
              rights[ group['g_id'] ] = String(this_rights);
            };
          });

          let change_check = "";
          let groups = dlg.data("groups");
          let k_a = keys(res['ok']['groups']);
          sort_by_string_key(k_a, res['ok']['groups'], 'g_name');

          for(let i in k_a) {
            let g_id = k_a[i];
            if(rights[g_id] !== undefined) {
              change_check += g_id+":"+rights[g_id]+";";
            };
          };

          if(change_check === dlg.data("change_check")) {
            dlg.animateHighlight("lightcoral", 200);
            return;
          };

          run_query({
            "action": "set_rights",
            "object": dlg.data("object"),
            "object_id": dlg.data("object_id"),
            "rights": rights
          }, function(res) {
            let done_func = dlg.data("on_done");
            dlg.dialog( "close" );
            if(done_func !== undefined) done_func();
          });
        },
      });
    };

    buttons.push({
      'text': allow_edit?'Отмена':'Закрыть',
      'click': function() {$(this).dialog( "close" );},
    });

    let dialog_options = {
      modal:true,
      maxHeight:1000,
      maxWidth:1800,
      minWidth:1200,
      width: "auto",
      height: "auto",
      buttons: buttons,
      close: function() {
        $(this).dialog("destroy");
        $(this).remove();
      }
    };

    dialog.appendTo("BODY");
    dialog.dialog( dialog_options );
  });
};

function rights_tds(object, rights_mask, allow_edit=false) {
  let ret = $([]);
  for(let i in r_keys) {
    let right = r_keys[i];
    if(!in_array(g_rights[right]['used_in'], object)) continue;
    let rclass = ((rights_mask & right) > 0)?"right_on":"right_off";
    ret = ret
     .add( $(SPAN).addClass("td")
       .append( $(SPAN).addClass(["right", rclass, "ns", "right_"+right])
         .data("right", right)
         .text(g_rights[right]['label'])
         .title(g_rights[right]['descr'])
         .click(!allow_edit?undefined:function() {
           let row = $(this).closest(".tr");
           let right = $(this).data("right");
           if($(this).hasClass("right_on")) {
             $(this).removeClass("right_on").addClass("right_off");

             for(let i in g_rights[right]['required_by']) {
               let rr = g_rights[right]['required_by'][i];
               row.find(".right_"+rr).removeClass("right_on").addClass("right_off");
             };
           } else {
             $(this).removeClass("right_off").addClass("right_on");
             for(let i in g_rights) {
               if(in_array(g_rights[i]['required_by'], right)) {
                 row.find(".right_"+i).removeClass("right_off").addClass("right_on");
               };
             };
             for(let i in g_rights[right]['conflict_with']) {
               let rr = g_rights[right]['conflict_with'][i];
               row.find(".right_"+rr).removeClass("right_on").addClass("right_off");
             };
           };
         })
       )
     )
    ;
  };
  return ret;
};

function rights_row(object, object_id, group_data, allow_edit=false) {
  let ret = $(DIV).addClass("tr").addClass("rights_row")
   .data("object", object)
   .data("object_id", object_id)
   .data("group", group_data)
  ;

  let title = group_data['g_descr'];
  if(group_data['fk_u_id'] !== undefined && group_data['fk_u_id'] !== null &&
     g_data['aux_userinfo'][ group_data['fk_u_id'] ] !== undefined
  ) {
    title += "\nДоступ добавлен: "+from_unix_time(group_data['ts'], false, "н.д.");
    title += "\nПользователем: "+g_data['aux_userinfo'][ group_data['fk_u_id'] ]['u_name']+" ("+
             g_data['aux_userinfo'][ group_data['fk_u_id'] ]['u_login']+")";
  } else if (group_data['_new'] !== undefined) {
    title += "\nДоступ добавлен: "+from_unix_time(unix_timestamp());
    title += "\nВами, только что";
  };

  ret
   .append( $(SPAN).addClass("td")
     .append( $(SPAN)
       .text(group_data['g_name'])
       .title(title)
     )
   )
  ;

  ret.append( rights_tds(object, group_data['rights'], allow_edit) );

  if(allow_edit) {
    ret
     .append( $(SPAN).addClass("td")
       .append( $(LABEL).addClass(["button", "ui-icon", "ui-icon-minus"])
         .click(function() {
           let dlg = $(this).closest(".dialog_start");
           let group = $(this).closest(".tr").data("group");
           let select = dlg.find("SELECT");
           select
            .append( $(OPTION)
              .text( group['g_name'] )
              .title( group['g_descr'] )
              .val( group['g_id'] )
            )
           ;
           $(this).closest(".tr").remove();
         })
       )
     )
    ;
  };

  return ret;
};

function edit_net_range(object, object_id) {
  let allow_edit = false;
  switch(object) {
  case "int_v4net_range":
    allow_edit = (g_data['net_rights'] & R_MANAGE_NET) > 0;
    break;
  case "ext_v4net_range":
    allow_edit = userinfo["is_admin"];
    break;
  default:
    error_at(object);
    return;
  };

  let query;
  if(object_id !== undefined) {
    query = {"action": "get_net_range", "object": object, "object_id": object_id};
  } else {
    query = {"action": "get_groups"};
  };
  run_query(query, function(res) {

    if(res['ok']['aux_userinfo'] !== undefined) {
      if(g_data['aux_userinfo'] === undefined) g_data['aux_userinfo'] = {};
      for(let u_id in res['ok']['aux_userinfo']) {
        g_data['aux_userinfo'][u_id] = res['ok']['aux_userinfo'][u_id];
      };
    };

    if(object_id === undefined) {
      let r_start;
      let r_stop;
      let style;

      switch(object) {
      case "int_v4net_range":
        r_start = g_data['net_addr'];
        r_stop = g_data['net_last_addr'];
        style = JSON.stringify(g_default_range_style);
        break;
      case "ext_v4net_range":
        r_start = g_data['net_addr'];
        r_stop = g_data['net_last_addr'];
        style = JSON.stringify(g_default_ext_range_style);

        break;
      default:
        error_at();
        return;
      };

      let groups = {};
      for(let i in res["ok"]["gs"]) {
        let g_id= res["ok"]["gs"][i]["g_id"];
        groups[g_id] = res["ok"]["gs"][i];
        groups[g_id]['rights'] = 0;
        groups[g_id]['ts'] = undefined;
        groups[g_id]['fk_u_id'] = null;
      };

      res = {
        "ok": {
          "groups": groups,
          "v4r_start": r_start,
          "v4r_stop": r_stop,
          "v4r_name": "",
          "v4r_descr": "",
          "v4r_id": undefined,
          "v4r_style": style,
          "v4r_icon": g_default_range_icon,
          "v4r_icon_style": JSON.stringify(g_default_range_icon_style),
          "ts": 0,
          "fk_u_id": null,
        }
      };
    };

    let title = "Диапазон адресов";
    switch(object) {
    case "int_v4net_range":
      title += " для сети "+g_data['net_name'];
      break;
    case "ext_v4net_range":
      break;
    default:
      error_at();
      return;
    };

    let dialog = $(DIV).addClass("dialog_start")
     .title(title)
     .data('object', object)
     .data('object_id', object_id)
     .data('groups', res['ok']['groups'])
     .data('r_data', res['ok'])
    ;

    $(DIV)
     .append( $(SPAN).text("Посл. изменение: ") )
     .append( $(SPAN).text(from_unix_time( res['ok']['ts'], false, 'н.д.' )) )
     .append( $(SPAN).addClass("min1em") )
     .append( res['ok']['fk_u_id'] === null?$(SPAN):$(SPAN)
       .text(
         g_data['aux_userinfo'][ res['ok']['fk_u_id'] ]['u_name']+" ("+
         g_data['aux_userinfo'][ res['ok']['fk_u_id'] ]['u_login']+")"
       )
     )
     .appendTo( dialog )
    ;

    $(DIV)
     .append( $(SPAN).text("Диапазон: ") )
     .append( $(INPUT)
       .prop({"id": "r_start", "placeholder": v4long2ip(res['ok']['v4r_start']), "readonly": !allow_edit})
       .val(v4long2ip(res['ok']['v4r_start']))
     )
     .append( $(SPAN).text(" - ") )
     .append( $(INPUT)
       .prop({"id": "r_stop", "placeholder": v4long2ip(res['ok']['v4r_stop']), "readonly": !allow_edit})
       .val(v4long2ip(res['ok']['v4r_stop']))
     )
     .appendTo( dialog )
    ;

    $(DIV)
     .append( $(SPAN).text("Название: ") )
     .append( $(INPUT)
       .prop({"id": "r_name", "readonly": !allow_edit})
       .val(res['ok']['v4r_name'])
     )
     .appendTo( dialog )
    ;

    let css;
    try {
      css = JSON.parse(res['ok']['v4r_style']);
    } catch(e) {
      css = g_default_range_style;
    };

    let sample_label;

    switch(object) {
    case "int_v4net_range":
      sample_label = $(LABEL).addClass("iprange")
       .html('&#x200b;')
       .prop("id", "r_style_sample")
       .css({"width": g_range_bar_width+"px", "margin-right": g_range_bar_width+"px"})
      ;
      break;
    case "ext_v4net_range":
      sample_label = $(LABEL)
       .html('&#x2503;')
       .prop("id", "r_style_sample")
      ;
      break;
    default:
      error_at();
      return;
    };

    $(DIV)
     .append( $(SPAN).html("CSS колонки: ").title("Например: {\"background-color\": \"red\"}") )
     .append( $(INPUT)
       .prop({"id": "r_style", "readonly": !allow_edit})
       .val(res['ok']['v4r_style'])
       .on("input change keyup", function() {
         let j = $(this).val();
         try {
           css = JSON.parse(j);
           $("#r_style_sample").css(css);
           $("#r_style_error").hide();
           $(this).css("background-color", "white");
         } catch(e) {
           $("#r_style_error").show();
           $(this).css("background-color", "lightcoral");
         };
       })
     )
     .append( $(SPAN).addClass("min1em") )
     .append( $(SPAN)
       .css({"position": "relative"})
       .append( sample_label )
     )
     .append( $(SPAN)
       .css({"padding-left": g_range_bar_width+g_range_bar_width+2+"px"})
       .append( $(LABEL)
         .prop("id", "r_style_error")
         .addClass(["ui-icon", "ui-icon-alert"])
         .css({"color": "red"})
         .title("Неверный JSON стиля")
         .hide()
       )
     )
     .appendTo( dialog )
    ;

    $(DIV)
     .append( $(A)
       .prop({"href": "https://mkkeck.github.io/jquery-ui-iconfont/#icons", "target": "_blank"})
       .dotted("Выбрать можно тут")
       .text("Значек диапазона ui-icon-*: ")
     )
     .append( $(INPUT)
       .prop({"id": "r_icon", "readonly": !allow_edit})
       .val(res['ok']['v4r_icon'])
       .on("input change keyup", function() {
         let v = $(this).val();
         let j = $("#r_icon_style").val();
         let css;
         try {
           css = JSON.parse(j);
           $("#r_icon_style").css("background-color", "white");
           $("#r_icon_style_error").hide();
         } catch(e) {
           $("#r_icon_style").css("background-color", "lightcoral");
           $("#r_icon_style_error").show();
           switch( $(this).closest(".dialog_start").data("object") ) {
           case "int_v4net_range":
             css = g_default_range_icon_style;
             break;
           case "ext_v4net_range":
             css = g_default_range_icon_style;
             break;
           default:
             error_at();
             return;
           };
         };
         if(!String(v).match(/^ui-icon-[\-a-z0-9]+$/)) {
           $("#r_icon").css("background-color", "lightcoral");
           $("#r_icon_error").show();
           $("#r_icon_span").empty();
         } else {
           $("#r_icon").css("background-color", "white");
           $("#r_icon_error").hide();
           $("#r_icon_span")
            .empty()
            .append( $(LABEL)
              .addClass(["ui-icon", v])
              .css(css)
            )
           ;
         };
       })
     )
     .append( $(SPAN).addClass("min1em") )
     .append( $(SPAN)
       .prop("id", "r_icon_span")
     )
     .append( $(SPAN).addClass("min1em") )
     .append( $(SPAN)
       .append( $(LABEL)
         .prop("id", "r_icon_error")
         .addClass(["ui-icon", "ui-icon-alert"])
         .css({"color": "red"})
         .title("Неверный класс значка. Должен начинаться на ui-icon-")
         .hide()
       )
     )
     .appendTo( dialog )
    ;

    $(DIV)
     .append( $(SPAN).text("CSS значка диапазона: ").title("Например: {\"color\": \"red\"}") )
     .append( $(INPUT)
       .prop({"id": "r_icon_style", "readonly": !allow_edit})
       .val(res['ok']['v4r_icon_style'])
       .on("input change keyup", function() {
         $("#r_icon").trigger("input");
       })
     )
     .append( $(SPAN).addClass("min1em") )
     .append( $(SPAN)
       .append( $(LABEL)
         .prop("id", "r_icon_style_error")
         .addClass(["ui-icon", "ui-icon-alert"])
         .css({"color": "red"})
         .title("Неверный JSON значка")
         .hide()
       )
     )
     .appendTo( dialog )
    ;

    $(DIV)
     .append( $(SPAN).text("Описание: ").css("vertical-align", "top") )
     .append( $(TEXTAREA)
       .prop({"id": "r_descr", "readonly": !allow_edit})
       .val(res['ok']['v4r_descr'])
     )
     .appendTo( dialog )
    ;

    $(DIV).text("Права доступа:")
     .css({"margin-top": "0.5em", "margin-bottom": "0.5em"})
     .appendTo( dialog )
    ;

    let table = $(DIV).addClass("table")
     .appendTo(dialog)
    ;

    let not_in_list = [];

    let k_a = keys(res['ok']['groups']);
    sort_by_string_key(k_a, res['ok']['groups'], 'g_name');

    for(let i in k_a) {
      let g_id = k_a[i];
      if(res['ok']['groups'][g_id]['rights'] == 0) {
        not_in_list.push(g_id);
        continue;
      };
      table.append( rights_row(object, object_id, res['ok']['groups'][g_id], allow_edit) );
    };

    if(allow_edit) {
      let last_row = $(DIV).addClass("tr");

      let select = $(SELECT)
       .append( $(OPTION).text("Выберете группу...").val(0) )
       .val(0)
       .tooltip({
         classes: { "ui-tooltip": "ui-corner-all ui-widget-shadow wsp tooltip" },
         items: "SELECT",
         content: function() {
           return $(this).find("OPTION:selected").prop("title");
         }
       })
      ;

      for(let i in not_in_list) {
        let g_id = not_in_list[i];
        select
         .append( $(OPTION)
           .text(res['ok']['groups'][g_id]['g_name'])
           .title(res['ok']['groups'][g_id]['g_descr'])
           .val(g_id)
         )
        ;
      };

      last_row
       .append( $(SPAN).addClass("td")
         .append( select )
       )
      ;

      last_row
       .append( rights_tds(object, 0, true) )
      ;

      last_row
       .append( $(SPAN).addClass("td")
         .append( $(LABEL).addClass(["button", "ui-icon", "ui-icon-plus"])
           .click(function() {
             let dialog = $(this).closest(".dialog_start");
             let select = dialog.find("SELECT");
             let option = select.find(":selected");
             let tr = $(this).closest(".tr");
             let g_id = select.val();
             if(g_id == 0) return;

             let this_rights = 0;

             tr.find(".right").each(function() {
               if( $(this).hasClass("right_on") ) {
                 this_rights = this_rights | $(this).data("right");
                 $(this).removeClass("right_on").addClass("right_off");
               };
             });

             if(this_rights == 0) return;

             let new_g_data = dialog.data("groups")[g_id];
             new_g_data['_new'] = true;
             new_g_data['rights'] = this_rights;
             let new_row = rights_row(dialog.data("object"), dialog.data("object_id"),
               new_g_data, true
             );
             new_row.insertBefore(tr);
             option.remove();
           })
         )
       )
      ;

      table.append( last_row );
    };

    let buttons = [];

    if(allow_edit && object_id !== undefined) {
      buttons.push({
        'class': 'left_dlg_button',
        'text': 'Удалить',
        'click': function() {
          let dlg = $(this);
          let object = dlg.data("object");

          show_confirm("Подтвердите удаление диапазона.\nВнимание: отмена операции будет невозможна!", function() {
            run_query({"action": "del_net_range", "object": dlg.data("object"), "object_id": String(dlg.data("object_id"))}, function(res) {

              dlg.dialog( "close" );

              switch(object) {
              case "int_v4net_range":
                window.location = "?action=view_v4&net="+g_data['net_addr']+"&masklen="+g_data['net_masklen']+
                                  (usedonly?"&usedonly":"")+(DEBUG?"&debug":"");
                break;
              case "ext_v4net_range":
                window.location = "?action=nav_v4&net="+g_data['net_addr']+"&masklen="+g_data['net_masklen']+
                                  (usedonly?"&usedonly":"")+(DEBUG?"&debug":"");
                break;
              default:
                error_at();
                return;
              };
            });
          });
        },
      });
    };

    if(allow_edit) {
      buttons.push({
        'text': object_id===undefined?'Создать':'Сохранить',
        'click': function() {
          let dlg = $(this);

          let rights = {};

          if(dlg.find("SELECT").val() != 0 &&
            dlg.find("SELECT").closest(".tr").find(".right_on").length > 0
          ) {
            dlg.find("SELECT").closest(".tr").animateHighlight("lightcoral", 200);
            return;
          };

          dlg.find(".rights_row").each(function() {
            let this_rights = 0;
            $(this).find(".right").each(function() {
              if($(this).hasClass("right_on")) {
                let right = $(this).data("right");
                this_rights |= right;
              };
            });
            if(this_rights > 0) {
              let group = $(this).data("group");
              rights[ group['g_id'] ] = String(this_rights);
            };
          });

          let r_start = v4ip2long($("#r_start").val());
          if(r_start === false) {
            $("#r_start").animateHighlight("red", 300);
            return;
          };

          let r_stop = v4ip2long($("#r_stop").val());
          if(r_stop === false) {
            $("#r_stop").animateHighlight("red", 300);
            return;
          };

          if(r_stop < r_start) {
            $("#r_start,#r_stop").animateHighlight("red", 300);
            return;
          };

          let object = dlg.data("object");

          switch(object) {
          case "int_v4net_range":
            if(r_start < g_data['net_addr']) {
              $("#r_start").animateHighlight("red", 300);
              return;
            };
            if(r_stop > g_data['net_last_addr']) {
              $("#r_stop").animateHighlight("red", 300);
              return;
            };
            break;
          case "ext_v4net_range":
            break;
          default:
            error_at();
            return;
          };

          try {
            JSON.parse(String($("#r_style").val()).trim());
          } catch(e) {
            $("#r_style").animateHighlight("red", 300);
            return;
          };

          try {
            JSON.parse(String($("#r_icon_style").val()).trim());
          } catch(e) {
            $("#r_icon_style").animateHighlight("red", 300);
            return;
          };

          if(!String($("#r_icon").val()).trim().match(/^ui-icon-[\-a-z0-9]+$/)) {
            $("#r_icon").animateHighlight("red", 300);
            return;
          };

          let query = {
            "action": "save_range",
            "object": dlg.data("object"),
            "object_id": dlg.data("object_id")===undefined?"":String(dlg.data("object_id")),
            "net_id": dlg.data("object") === "int_v4net_range"?String(g_data['net_id']):null,
            "rights": rights,
            "r_start": String(r_start),
            "r_stop": String(r_stop),
            "r_name": String($("#r_name").val()).trim(),
            "r_descr": String($("#r_descr").val()).trim(),
            "r_style": String($("#r_style").val()).trim(),
            "r_icon": String($("#r_icon").val()).trim(),
            "r_icon_style": String($("#r_icon_style").val()).trim(),
          };
          run_query(query, function(res) {
            dlg.dialog( "close" );

            switch(object) {
            case "int_v4net_range":
              window.location = "?action=view_v4&net="+g_data['net_addr']+"&masklen="+g_data['net_masklen']+
                                (usedonly?"&usedonly":"")+(DEBUG?"&debug":"");
              break;
            case "ext_v4net_range":
              window.location = "?action=nav_v4&net="+g_data['net_addr']+"&masklen="+g_data['net_masklen']+
                                (usedonly?"&usedonly":"")+(DEBUG?"&debug":"");
              break;
            default:
              error_at();
              return;
            };
          });
        },
      });
    };

    buttons.push({
      'text': allow_edit?'Отмена':'Закрыть',
      'click': function() {$(this).dialog( "close" );},
    });

    let dialog_options = {
      modal:true,
      maxHeight:1000,
      maxWidth:1800,
      minWidth:1200,
      width: "auto",
      height: "auto",
      buttons: buttons,
      close: function() {
        $(this).dialog("destroy");
        $(this).remove();
      }
    };

    dialog.appendTo("BODY");
    dialog.dialog( dialog_options );

    $("#r_style").trigger("input");
    $("#r_icon").trigger("input");
  });
};

function take_v4net(net, masklen) {
  run_query({"action": "list_net_templates"}, function(res) {
    if(res['ok']['templates'].length == 0) {
      show_dialog("В БД нет ни одного шаблона сети. Обратитесь к администратору.");
      return;
    };

    let dialog = $(DIV).addClass("dialog_start")
     .title("Занятие сети "+v4long2ip(net)+"/"+masklen)
     .data("net", net)
     .data("masklen", masklen)
    ;

    let select = $(SELECT)
     .append( $(OPTION).text("Выберите шаблон...").val(0) )
     .val(0)
    ;
    for(let i in res['ok']['templates']) {
      select
       .append( $(OPTION).text(res['ok']['templates'][i]['tp_name'])
         .val(res['ok']['templates'][i]['tp_id'])
       )
      ;
    };

    dialog
     .append( $(DIV)
       .append( select )
     )
    ;

    let buttons = [];
    buttons.push({
      'text': 'Занять',
      'click': function() {
        let dlg = $(this);
        let net = dlg.data("net");
        let masklen = dlg.data("masklen");
        let tp_id = dlg.find("SELECT").val();

        if(tp_id == 0) {
          dlg.find("SELECT").animateHighlight("red", 200);
          return;
        };

        run_query({"action": "take_net", "v": "4", "tp_id": String(tp_id),
                   "net": String(net), "masklen": String(masklen)},
                  function(res) {
          window.location = "?action=view_v4&net="+net+"&masklen="+masklen+"&is_new"+
                            (usedonly?"&usedonly":"")+(DEBUG?"&debug":"");
        });
      }, //click: function
    });

    buttons.push({
      'text': 'Отмена',
      'click': function() {$(this).dialog( "close" );},
    });

    let dialog_options = {
      modal:true,
      //maxHeight:1000,
      //maxWidth:1800,
      minWidth: 600,
      width: 600,
      height: "auto",
      buttons: buttons,
      close: function() {
        $(this).dialog("destroy");
        $(this).remove();
      }
    };

    dialog.appendTo("BODY");
    dialog.dialog( dialog_options );
     
  });
};

function net_cols_edit() {
  run_query({"action": "get_netcols"}, function(res) {

    let dialog = $(DIV).addClass("dialog_start")
     .title("Выбор полей для сети "+v4long2ip(g_data['net_addr'])+"/"+g_data['net_masklen'])
    ;

    let table = $(DIV).addClass("table")
     .append( $(DIV).addClass("thead")
       .append( $(SPAN).addClass("th").text("Поле") )
       .append( $(SPAN).addClass("th").text("Вкл") )
       .append( $(SPAN).addClass("th").text("Тип") )
       .append( $(SPAN).addClass("th").text("RegExp") )
     )
     .appendTo(dialog)
    ;

    for(let i in res['ok']['netcols']) {
      let ic_id = res['ok']['netcols'][i]['ic_id'];

      let tr = $(DIV).addClass("tr")
       .append( $(SPAN).addClass("td")
         .append( $(SPAN)
           .text(res['ok']['netcols'][i]['ic_name'])
           .title(res['ok']['netcols'][i]['ic_descr']+"\n"+"API name: "+res['ok']['netcols'][i]['ic_api_name'])
         )
       )
       .append( $(SPAN).addClass("td")
         .append( $(INPUT)
           .data("ic_id", ic_id)
           .data("initial", g_data['net_cols'][ic_id] !== undefined)
           .prop({"type": "checkbox", "checked": g_data['net_cols'][ic_id] !== undefined})
         )
       )
       .append( $(SPAN).addClass("td")
         .append( $(SPAN)
           .text(res['ok']['netcols'][i]['ic_type'])
         )
       )
       .append( $(SPAN).addClass("td")
         .append( $(SPAN)
           .text(res['ok']['netcols'][i]['ic_regexp'])
         )
       )
       .appendTo(table)
      ;
    };

    let buttons = [];
    buttons.push({
      'text': 'Сохранить',
      'click': function() {
        let dlg = $(this);

        let on=[];
        let off=[];

        dlg.find("INPUT[type=checkbox]").each(function() {
          let ic_id = $(this).data("ic_id");
          let state = $(this).is(":checked");
          let initial = $(this).data("initial");

          if(state !== initial) {
            if(state) {
              on.push(String(ic_id));
            } else {
              off.push(String(ic_id));
            };
          };
        });

        if(on.length > 0 || off.length > 0) {
          show_confirm_checkbox("Внимание!\nОтключение полей приведет к удалению ВСЕХ данных,\nсвязаных с IP адресами и отключаемыми полями!\n"+
                                "Отмена будет невозможна!", function() {
            run_query({"action": "net_set_cols", "net_id": String(g_data['net_id']), "v": g_data["v"], "on": on, "off": off}, function(res) {
              window.location = "?action=view_v"+g_data["v"]+"&net="+g_data['net_addr']+"&masklen="+g_data['net_masklen']+
                                (usedonly?"&usedonly":"")+(DEBUG?"&debug":"");
            });
          }, {}, off.length == 0);
        } else {
          dlg.dialog( "close" );
        };
      },
    });

    buttons.push({
      'text': 'Отмена',
      'click': function() {$(this).dialog( "close" );},
    });

    let dialog_options = {
      modal:true,
      //maxHeight:1000,
      //maxWidth:1800,
      minWidth: 600,
      width: 600,
      height: "auto",
      buttons: buttons,
      close: function() {
        $(this).dialog("destroy");
        $(this).remove();
      }
    };

    dialog.appendTo("BODY");
    dialog.dialog( dialog_options );
     
  });
};

function actionVlanDomains() {
  workarea.empty();
  fixed_div.empty();

  run_query({"action": "list_vlan_domains"}, function(res) {
    if(res['ok']['aux_userinfo'] !== undefined) {
      if(g_data['aux_userinfo'] === undefined) g_data['aux_userinfo'] = {};
      for(let u_id in res['ok']['aux_userinfo']) {
        g_data['aux_userinfo'][u_id] = res['ok']['aux_userinfo'][u_id];
      };
    };

    g_data = res['ok'];

    let table = $(DIV).addClass("table")
     .css({"font-size": "larger"})
     .append( $(DIV).addClass("thead")
       .append( $(SPAN).addClass("th")
         .text("VLAN домен")
       )
       .append( $(SPAN).addClass("th")
         .text("Занято")
       )
       .append( $(SPAN).addClass("th")
         .text("Сетей v4")
       )
       .append( $(SPAN).addClass("th")
         .text("Адресов v4")
       )
       .append( $(SPAN).addClass("th")
         .text("Сетей v6")
       )
       .append( $(SPAN).addClass("th")
         .text("Адресов v6")
       )
     )
     .appendTo(workarea)
    ;

    for(let i in res['ok']['vds']) {
      let vd = res['ok']['vds'][i];
      let tr = $(DIV).addClass("tr")
       .data("id", vd['vd_id'])
      ;

      tr
       .append( $(SPAN).addClass("td")
         .append( $(A)
           .addClass("vd"+vd['vd_id'])
           .prop("href", "?action=view_vlan_domain&id="+vd['vd_id']+(DEBUG?"&debug":""))
           .text(vd['vd_name'])
           .title(vd['vd_descr'])
         )
       )
       .append( $(SPAN).addClass("td")
         .text(vd['num_taken'])
       )
       .append( $(SPAN).addClass("td")
         .text(vd['v4nets'])
       )
       .append( $(SPAN).addClass("td")
         .text(vd['v4ips'])
       )
       .append( $(SPAN).addClass("td")
         .text(vd['v6nets'])
       )
       .append( $(SPAN).addClass("td")
         .text(vd['v6ips'])
       )
      ;

      tr.appendTo(table);
    };

    if(userinfo['is_admin']) {
      let tr = $(DIV).addClass("tr")
       .append( $(SPAN).addClass("td")
         .append( $(INPUT).addClass("new_vlan_domain_name")
           .enterKey(function() {
             $(".vd_add_btn").trigger("click")
           })
         )
         .append( $(SPAN).addClass("min1em") )
         .append( $(LABEL).addClass(["button", "ui-icon", "ui-icon-plus"])
           .addClass("vd_add_btn")
           .title("Добавить")
           .click(function() {
             let new_vd_name = $("INPUT.new_vlan_domain_name").val();
             if(new_vd_name === undefined) { error_at(); return; };
             new_vd_name = String(new_vd_name).trim();
             if(!new_vd_name.match(/^[a-zA-Z][a-zA-Z_0-9]*$/)) {
               $("INPUT.new_vlan_domain_name").animateHighlight("red", 300);
               return;
             };

             for(let i in g_data['vds']) {
               if(String(g_data['vds'][i]['vd_name']).toLowerCase() == new_vd_name.toLowerCase()) {
                 $(".vd"+g_data['vds'][i]['vd_id']+",INPUT.new_vlan_domain_name").animateHighlight("red", 300);
                 return;
               };
             };

             run_query({"action": "add_vdom", "name": new_vd_name}, function(res) {
               window.location = "?action=view_vlan_domain&id="+res['ok']['vd_id']+(DEBUG?"&debug":"");
             });
           })
         )
       )
       .append( $(SPAN).addClass("td") )
       .append( $(SPAN).addClass("td") )
       .append( $(SPAN).addClass("td") )
       .append( $(SPAN).addClass("td") )
       .append( $(SPAN).addClass("td") )
       .appendTo( table )
      ;
    };

  });
};

function vlan_row(row_data) {
  let empty_colspan = 6;

  let tr = $(TR).addClass("row")
   .data("row_data", row_data)
  ;

  let vlan_td = $(TD).addClass("wsp")
  ;

  let ranges_span = $(SPAN)
   .css({"width": (g_range_bar_width+g_range_bar_margin)*g_data["vdom_ranges"].length, "display": "inline-block"})
  ;

  for(let i in g_data["vdom_ranges"]) {
    let r_label = $(LABEL).addClass("iprange");
    r_label.html('&#x200b;');
    r_label.css({"left": ((g_range_bar_width+g_range_bar_margin)*i)+"px",
                 "width": g_range_bar_width+"px",
                 "margin-right": g_range_bar_width+"px",
    });
    if(row_data['ranges'][i]['in_range'] !== undefined) {
      r_label.addClass("vlanrange_shown");
      if(g_data["vdom_ranges"][i]['vr_style'] != "{}") {
        try {
          let r_label_css = JSON.parse(g_data["vdom_ranges"][i]['vr_style']);
          r_label.css(r_label_css);
        } catch(e) {
          r_label.css(g_default_range_style);

        };
      } else {
        r_label.css(g_default_range_style);
      };
      r_label.title(vrange_title(g_data["vdom_ranges"][i]));
      r_label.data("r_i", i);
    };
    ranges_span.append( r_label );
  };

  vlan_td.append( ranges_span );

  let can_edit = false;
  if(row_data['rights'] !== undefined &&
     (row_data['rights'] & R_EDIT_IP_VLAN) > 0 &&
     ((row_data['rights'] & R_DENYIP) == 0 ||
      (row_data['rights'] & R_IGNORE_R_DENY) > 0
     )
  ) {
    can_edit = true;
  };


  if(row_data['is_empty'] !== undefined) {
    vlan_td.appendTo( tr );
    let empty_td = $(TD).prop("colspan", empty_colspan).addClass("empty_td");
    if(can_edit) {
      empty_td
       .append( $(SPAN).text("Занять: ") )
       .append( $(LABEL).text(row_data['start'])
         .addClass("button")
         .data("take_type", "vlan")
         .data("vlan", row_data['start'])
         .click(function() { take_vlan($(this)); })
       )
      ;
      if((row_data['stop'] - row_data['start']) > 1) {
        let next_vlan = row_data['start'] + 1;
        let next_vlan_t = String(next_vlan);
        let last_vlan_t = String(row_data['stop']);

        let val = "";
        let i=1;

        while(i < next_vlan_t.length && i < last_vlan_t.length) {
          if(next_vlan_t.substring(0, i) == last_vlan_t.substring(0, i)) {
            val = next_vlan_t.substring(0, i);
            i++;
          } else {
            break;
          };
        };

        empty_td
         .append( $(SPAN).text(" - ") )
         .append( $(INPUT)
           .css({"width": "8em"})
           .addClass("any_vlan")
           .val(val)
           .data("first", next_vlan)
           .data("last", row_data['stop']-1)
           .enterKey(function() { $(this).closest(".row").find(".take_any_btn").click(); })
         )
         .append( $(LABEL).text("+")
           .addClass("button")
           .addClass("take_any_btn")
           .data("take_type", "any_vlan")
           .data("first", next_vlan)
           .data("last", row_data['stop']-1)
           .click(function() { take_vlan($(this)); })
         )
        ;
      };
      if(row_data['start'] !== row_data['stop']) {
        empty_td
         .append( $(SPAN).text(" - ") )
         .append( $(LABEL).text(row_data['stop'])
           .addClass("button")
           .data("vlan", row_data['stop'])
           .data("take_type", "vlan")
           .click(function() { take_vlan($(this)); })
         )
        ;
      };
    } else {
      if(row_data['start'] === row_data['stop']) {
        empty_td
         .append( $(SPAN).text("Свободно: ") )
         .append( $(SPAN).text(row_data['start'])
         )
        ;
      } else {
        empty_td
         .append( $(SPAN).text("Свободно: ") )
         .append( $(SPAN).text(row_data['start'])
         )
         .append( $(SPAN).text(" - ") )
         .append( $(SPAN).text(row_data['stop'])
         )
        ;
      };
    };
    empty_td.appendTo( tr );
  } else {
    // menu
    vlan_td
     .append( $(LABEL)
       .addClass("button")
       .addClass("ns")
       .addClass(["ui-icon", "ui-icon-bars"])
       .css({"float": "right", "clear": "none"})
       .click(function(e) {
         e.stopPropagation();
         vlan_menu($(this));
       })
     )
    ;
    //
    vlan_td.append( $(SPAN).text(row_data['vlan_number']).addClass("vlan_number") );

    vlan_td
     .append( $(SPAN)
       .addClass("ns")
       .css({"display": "inline-block", "min-width": "2em"})
       //.html('&#x200b;')
     )
    ;

    vlan_td.tooltip({
      classes: { "ui-tooltip": "ui-corner-all ui-widget-shadow wsp tooltip" },
      items: "SPAN.vlan_number",
      content: function() {
        if( $("UL").length > 0 ) return undefined;
        let row = $(this).closest(".row");
        let row_data = row.data("row_data");
        let lines=[];
        if(row_data['ts'] > 0) {
          lines.push("Последнее изменение: "+from_unix_time(row_data['ts'], false, 'н/д'));
          if(row_data['fk_u_id'] !== null && g_data['aux_userinfo'][row_data['fk_u_id']] != undefined) {
            let user_row = g_data['aux_userinfo'][row_data['fk_u_id']];
            lines.push("\t"+user_row['u_name']+" ("+user_row['u_login']+")");
          };
        };
        return lines.join("\n");
      }
    });


    vlan_td.appendTo( tr );

    tr
     .append( $(TD)
       .append( vlan_val_elm(row_data, "vlan_name", g_edit_all) )
     )
     .append( $(TD)
       .append( vlan_val_elm(row_data, "vlan_descr", g_edit_all) )
     )
     .append( $(TD)
       .text( row_data['v4nets'] )
     )
     .append( $(TD)
       .text( row_data['v4ips'] )
     )
     .append( $(TD)
       .text( row_data['v6nets'] )
     )
     .append( $(TD)
       .text( row_data['v6ips'] )
     )
    ;

  };

  if(can_edit) {
    tr
     .on("click dblclick", function(e) {
       if ((e.type == "click" && e.ctrlKey) ||
           e.type == "dblclick"
       ) {
         e.stopPropagation();
         let row_data = $(this).data("row_data");
         let td;
         if(e.target.nodeName == "TD") {
           td = $(e.target);
         } else {
           td = $(e.target).closest("TD");
         };
         $(this).find(".vlan_view").each(function() {
           $(this).replaceWith(vlan_val_elm(row_data, $(this).data('prop'), true));
         });
         let focuson = td.find(".vlan_edit");

         if(focuson.length > 0) {
           focuson.focus();
         };
       };
     })
    ;
  };

  return tr;
};

function actionViewVlanDomain() {
  workarea.empty();
  fixed_div.empty();

  let vd_id = getUrlParameter("id", undefined);

  if(vd_id === undefined || !String(vd_id).match(/^\d+$/)) { error_at(); return; };

  run_query({"action": "view_vlan_domain", "id": String(vd_id)}, function(res) {
    g_data = res['ok'];
    document.title = "IPDB: VLAN домен "+res['ok']['vd_name'];

    fixed_div
     .append( $(DIV)
       .css({"display": "flex", "align-items": "center"})
       .append( $(LABEL).addClass(["ui-icon", "ui-icon-info", "button"])
         .css({"margin-left": "0.5em"})
         .click(function() {
           g_show_vdom_info = !g_show_vdom_info;
           $("#vdom_info").toggle(g_show_vdom_info);
           save_local("show_vdom_info", g_show_vdom_info);
         })
       )
       .append( $(SPAN).addClass("min1em") )
       .append( !userinfo['is_admin']?$(LABEL):$(LABEL)
         .addClass(["ui-icon", "ui-icon-edit"])
         .title("Редактировать. Можно также сделать CTRL-Click или Dbl-Click на поле")
         .click(function() {
           let elm = $("#vd_name_editable");
           if(elm.hasClass("editable_edit")) {
             $(this).title("Редактировать. Можно также сделать CTRL-Click или Dbl-Click на поле")
           } else {
             $(this).title("Отменить редактирование. Также можно нажать ESC когда курсор в поле ввода");
           };
           elm.trigger("editable_toggle");
         })
       )
       .append( $(SPAN)
         .css({"font-size": "xx-large"})
         .append(
           editable_elm({
             'object': 'vdom',
             'prop': 'vd_name',
             'id': String(g_data['vd_id']),
             '_edit_css': { 'width': '50em' },
             '_elm_id': 'vd_name_editable',
             '_after_save': function(elm, new_val) {
               g_data['vd_name'] = new_val;
               $("#vdom_changed_ts").text( from_unix_time( unix_timestamp() ) );
               $("#vdom_changed_user").text(userinfo['name'] +" ("+userinfo['login']+")"); 
             }
           })
         )
       )
     )
    ;

    g_show_vdom_info = get_local("show_vdom_info", g_show_vdom_info);

    var info_div = $(DIV)
     .prop("id", "vdom_info")
    ;

    fixed_div
     .append( info_div.toggle(g_show_vdom_info) )
    ;

    info_div
     .append( $(DIV)
       .append( !userinfo['is_admin']?$(LABEL):$(LABEL)
         .addClass(["button", "ui-icon", "ui-icon-trash"])
         .title("Удалить домен")
         .click(function() {
           show_confirm_checkbox("Подтвердите удаление домена.\nВнимание: отменить операцию будет невозможно!", function() {
             run_query({"action": "del_vdom", "object_id": String(g_data['vd_id'])}, function(res) {
               g_autosave_changes = 0;
               window.location = "?action=vlan_domains"+(DEBUG?"&debug":"");
             });
           });
         })
       )
     )
    ;

    if(res['ok']['ts'] > 0 && res['ok']['fk_u_id'] !== null &&
       res['ok']['fk_u_id'] !== undefined && g_data['aux_userinfo'][ res['ok']['fk_u_id'] ] != undefined
    ) {
      info_div
       .append( $(DIV)
         .append( $(SPAN).text("Изменена: ") )
         .append( $(SPAN).text(from_unix_time(res['ok']['ts']) )
           .prop("id", "vdom_changed_ts")
         )
         .append( $(SPAN).text(" Пользователем: ") )
         .append( $(SPAN)
           .text(g_data['aux_userinfo'][ res['ok']['fk_u_id'] ]['u_name']+" ("+
                 g_data['aux_userinfo'][ res['ok']['fk_u_id'] ]['u_login']+")"
           )
           .prop("id", "vdom_changed_user")
         )
       )
      ;
    };

    info_div
     .append( $(DIV)
       .append( !userinfo['is_admin']?$(LABEL):$(LABEL)
         .addClass(["ui-icon", "ui-icon-edit"])
         .css({"vertical-align": "top"})
         .title("Редактировать. Можно также сделать CTRL-Click или Dbl-Click на поле")
         .click(function() {
           let elm = $("#vd_descr_editable");
           if(elm.hasClass("editable_edit")) {
             $(this).title("Редактировать. Можно также сделать CTRL-Click или Dbl-Click на поле")
           } else {
             $(this).title("Отменить редактирование. Также можно нажать ESC когда курсор в поле ввода");
           };
           elm.trigger("editable_toggle");
         })
       )
       .append(
         editable_elm({
           'object': 'vdom',
           'prop': 'vd_descr',
           'id': String(g_data['vd_id']),
           '_view_classes': ["wsp"],
           '_view_css': {"display": "inline-block", "border": "2px inset gray", "padding": "2px"},
           '_edit_css': { 'width': '50em', 'min-height': '20em' },
           '_elm_id': 'vd_descr_editable',
           '_after_save': function(elm, new_val) {
             g_data['vd_descr'] = new_val;
             $("#vdom_changed_ts").text( from_unix_time( unix_timestamp() ) );
             $("#vdom_changed_user").text(userinfo['name'] +" ("+userinfo['login']+")"); 
           }
         })
       )
     )
    ;

    g_edit_all = get_local("edit_all", g_edit_all);

    fixed_div
     .append( $(DIV)
       .append( $(SPAN).text("Всего: ") )
       .append( $(SPAN).text("Сетей v4: ") )
       .append( $(SPAN).text(g_data['v4nets']) )
       .append( $(SPAN).html("&nbsp;&nbsp;Адресов v4: ") )
       .append( $(SPAN).text(g_data['v4ips']) )
       .append( $(SPAN).html("&nbsp;&nbsp;Сетей v6: ") )
       .append( $(SPAN).text(g_data['v6nets']) )
       .append( $(SPAN).html("&nbsp;&nbsp;Адресов v6: ") )
       .append( $(SPAN).text(g_data['v6ips']) )
     )
    ;

    fixed_div
     .append( $(DIV)
       .append( $(SPAN)
         .append( $(LABEL)
           .text("Редактировать все: ")
           .prop("for", "edit_all")
         )
         .append( $(INPUT)
           .prop({"id": "edit_all", "type": "checkbox", "checked": g_edit_all})
           .on("change", function() {
             let state = $(this).is(":checked");
             save_local("edit_all", state);


             $(".main_table").find("TBODY").find("TR").each(function() {
               let row = $(this);
               let row_row_data = row.data("row_data");
               if(row_row_data['is_taken'] !== undefined) {
                 row.find(".vlan_value").each(function() {
                   let prop = $(this).data("prop");
                   let changed = $(this).data("autosave_changed");
                   if(changed === undefined || changed === false) {
                     let new_elm = vlan_val_elm(row_row_data, prop, state);
                     $(this).replaceWith(new_elm);
                   };
                 });
               };
             });
           })
         )
       )
     )
    ;

    let table = $(TABLE).addClass("main_table")
    ;

    let thead = $(TR)
    ;

    thead
     .append( $(TH)
       .text("VLAN")
       .append( !userinfo['is_admin']?$(LABEL):$(LABEL)
         .addClass(["button", "ui-icon", "ui-icon-plus"])
         .title("Добавить диапазон")
         .css({"float": "left"})
         .click(function() {
           if(g_autosave_changes > 0) {
             show_dialog("На странице есть несохраненные поля.\nСперва сохраните изменения.");
             return;
           };
           edit_vdom_range(undefined);
         })
       )
     )
     .append( $(TH)
       .text("Имя")
     )
     .append( $(TH)
       .text("Описание")
     )
     .append( $(TH)
       .text("Сетей v4")
     )
     .append( $(TH)
       .text("Адресов v4")
     )
     .append( $(TH)
       .text("Сетей v6")
     )
     .append( $(TH)
       .text("Адресов v6")
     )
    ;



    table
     .append( $(THEAD)
       .append( thead )
     )
    ;

    let tbody = $(TBODY);


    for(let vlan_i in res['ok']['vlans']) {
      let row_data = res['ok']['vlans'][vlan_i];
      let tr = vlan_row(row_data);
      tr.appendTo( tbody );

    };

    table.append( tbody );
    table.appendTo( workarea );

    table.tooltip({
      classes: { "ui-tooltip": "ui-corner-all ui-widget-shadow wsp tooltip" },
      items: ".vlanrange",
      content: function() {
        let r_i = $(this).data("r_i");
        if(r_i === undefined) return;
        return range_title(g_data['vdom_ranges'][r_i]);
      }
    });

    if(userinfo['is_admin']) {
      table.find(".vlanrange_shown").on("click dblclick", function(e) {
        if ((e.type == "click" && e.ctrlKey) ||
            e.type == "dblclick"
        ) {
          e.stopPropagation();
          let r_i = $(this).data("r_i");
          if(r_i === undefined) return;
          if(g_autosave_changes > 0) {
            show_dialog("На странице есть несохраненные поля.\nСперва сохраните изменения.");
            return;
          };
          edit_vdom_range(g_data['vdom_ranges'][r_i]['vr_id']);
        };
      });
    };
  });
};

function take_vlan(elm) {
  let row = elm.closest(".row");
  let prev_row_data = row.data("row_data");
  let take_type = elm.data("take_type");
  if(take_type == undefined) { error_at(); return; };
  if(prev_row_data == undefined) { error_at(); return; };

  let take_vlan = undefined;
  if(take_type === "vlan") {
    take_vlan = elm.data("vlan");
  } else if(take_type === "any_vlan") {
    let v = row.find(".any_vlan").val();
    take_vlan = v;
    let first = elm.data("first");
    let last = elm.data("last");
    if(take_vlan < first || take_vlan > last) {
      row.find(".any_vlan").animateHighlight("red", 500);
      return;
    };
  } else {
    error_at(); return;
  };

  if(take_vlan === undefined) { error_at(); return; };

  run_query({"action": "take_vlan", "take_vlan": String((take_vlan >>> 0)), "ranges_orig": g_data['ranges_orig'],
            "vd_id": String(g_data['vd_id'])
  }, function(res) {

    let new_row_data = res['ok']['row_data'];
    let new_vlan_row = vlan_row(new_row_data);
    row.replaceWith( new_vlan_row );

    let prev_start = prev_row_data['start'];
    let prev_stop = prev_row_data['stop'];

    if(prev_start != prev_stop) {
      if(take_vlan > prev_start) {
        let before_data = dup(prev_row_data);
        before_data['stop'] = Number(take_vlan) - 1;
        let before_row = vlan_row(before_data);
        before_row.insertBefore(new_vlan_row);
      };
      if(take_vlan < prev_stop) {
        let after_data = dup(prev_row_data);
        after_data['start'] = Number(take_vlan) + 1;
        let after_row = vlan_row(after_data);
        after_row.insertAfter(new_vlan_row);
      };
    };
  });
};

function vlan_menu(elm) {
  $("UL.popupmenu").remove();
  let row = elm.closest(".row");
  let row_data = row.data("row_data");
  
  let menu = $(UL)
   .addClass("popupmenu")
   .css({"background-color": "white", "border": "1px solid black", "display": "inline-block", "z-index": 100})
   .css({"padding": "0.2em"})
   .css({"position": "absolute"})
   .append( $(LI)
     .title("Закрыть меню")
     .append( $(DIV)
       //.css({"display": "inline-block"})
       .append( $(LABEL).addClass(["ui-icon", "ui-icon-arrowreturn-1-w"]) )
       .append( $(SPAN).html("&#x200b;") )
       .click(function(e) {
         e.stopPropagation();
         $("UL.popupmenu").remove();
       })
     )
   )
  ;


  if((row_data['rights'] & R_EDIT_IP_VLAN) != 0 &&
     (row_data['rights'] & R_VIEW_NET_IPS) != 0 &&
     ((row_data['rights'] & R_DENYIP) == 0 ||
      (row_data['rights'] & R_IGNORE_R_DENY) != 0
     )
  ) {

    if(row.find(".vlan_view").length > 0) {
      menu
       .append( $(LI)
         .append( $(DIV)
           .title("Также можно сделать CTRL-Click или dbl-Click на строке...")
           .append( $(LABEL).addClass(["ui-icon", "ui-icon-edit"]) )
           .append( $(SPAN).html("Редактировать&#x20F0;") )
           .click(function(e) {
             e.stopPropagation();

             let row = $(this).closest("TR");

             row.find(".vlan_view").each(function() {
               $(this).replaceWith(vlan_val_elm(row_data, $(this).data('prop'), true));
             });
             $("UL.popupmenu").remove();

             row.find(".vlan_edit").first().focus();
           })
         )
       )
      ;
    };

    if(row.find(".vlan_edit").length > 0) {
      menu
       .append( $(LI)
         .append( $(DIV)
           //.css({"display": "inline-block"})
           .append( $(LABEL).addClass(["ui-icon", "ui-icon-undo"]) )
           .append( $(SPAN).text("Перестать редактировать") )
           .click(function(e) {
             e.stopPropagation();

             let row = $(this).closest("TR");

             row.find(".vlan_edit").each(function() {
               let changed = $(this).data("autosave_changed");
               if(changed) {
                 g_autosave_changes--;
               };
               $(this).replaceWith(vlan_val_elm(row_data, $(this).data('prop'), false));
             });
             if(g_autosave_changes < 0) {
               error_at();
               return;
             } else if(g_autosave_changes == 0) {
               $("#autosave_btn").css({"color": "gray"});
             } else {
               $("#autosave_btn").css({"color": "yellow"});
             };
             $("UL.popupmenu").remove();
           })
         )
       )
      ;
    };

    menu
     .append( $(LI)
       .append( $(DIV)
         //.css({"display": "inline-block"})
         .append( $(LABEL).addClass(["ui-icon", "ui-icon-trash"]) )
         .append( $(SPAN).text("Освободить") )
         .click(function(e) {
           e.stopPropagation();
           let row = $(this).closest("TR");
           let row_data = row.data("row_data");
           if(row_data === undefined) { error_at(); return; };
           show_confirm("Подтвердите освобождение VLAN "+row_data['vlan_number']+
                        "\nВнимание: отмена будет невозможна", function() {
             let vlan_id = row_data['vlan_id'];
             run_query({"action": "free_vlan", "id": String(vlan_id)}, function(res) {

               row.find(".vlan_edit").each(function() {
                 let changed = $(this).data("autosave_changed");
                 if(changed) {
                   g_autosave_changes--;
                 };
               });
               if(g_autosave_changes < 0) {
                 error_at();
                 return;
               } else if(g_autosave_changes == 0) {
                 $("#autosave_btn").css({"color": "gray"});
               } else {
                 $("#autosave_btn").css({"color": "yellow"});
               };

               $("UL.popupmenu").remove();
               let new_vlan_data = {};
               new_vlan_data['ranges'] = row_data['ranges'];
               new_vlan_data['rights'] = row_data['rights'];
               new_vlan_data['is_empty'] = 1;
               new_vlan_data['start'] = row_data['vlan_number'];
               new_vlan_data['stop'] = row_data['vlan_number'];

               row.replaceWith( vlan_row(new_vlan_data) );
             });
           });
         })
       )
     )
    ;

  };

  //let elm_offset = elm.offset();
  //let elm_width = elm.width();

  let td_width = elm.closest("TD").width();

  menu.css({"top": "0px", "left": td_width+10+"px"});

  menu.appendTo(elm.closest("TD"));

  menu.menu();

  menu.on("click dblclick", function(e) { e.stopPropagation(); });

  $(".tooltip").remove();
};

function edit_vdom_range(object_id) {
  let allow_edit = false;
  allow_edit = userinfo["is_admin"];

  let query;
  if(object_id !== undefined) {
    query = {"action": "get_vdom_range", "object_id": object_id};
  } else {
    query = {"action": "get_groups"};
  };
  run_query(query, function(res) {

    if(res['ok']['aux_userinfo'] !== undefined) {
      if(g_data['aux_userinfo'] === undefined) g_data['aux_userinfo'] = {};
      for(let u_id in res['ok']['aux_userinfo']) {
        g_data['aux_userinfo'][u_id] = res['ok']['aux_userinfo'][u_id];
      };
    };

    if(object_id === undefined) {
      let r_start;
      let r_stop;
      let style;

      r_start = 1;
      r_stop = g_data['vd_max_num'];
      style = JSON.stringify(g_default_range_style);

      let groups = {};
      for(let i in res["ok"]["gs"]) {
        let g_id= res["ok"]["gs"][i]["g_id"];
        groups[g_id] = res["ok"]["gs"][i];
        groups[g_id]['rights'] = 0;
        groups[g_id]['ts'] = undefined;
        groups[g_id]['fk_u_id'] = null;
      };

      res = {
        "ok": {
          "groups": groups,
          "vr_start": r_start,
          "vr_stop": r_stop,
          "vr_name": "",
          "vr_descr": "",
          "vr_id": undefined,
          "vr_style": style,
          "vr_icon": g_default_range_icon,
          "vr_icon_style": JSON.stringify(g_default_range_icon_style),
          "ts": 0,
          "fk_u_id": null,
        }
      };
    };

    let title = "Диапазон VLAN";

    let dialog = $(DIV).addClass("dialog_start")
     .title(title)
     .data('object_id', object_id)
     .data('groups', res['ok']['groups'])
     .data('r_data', res['ok'])
    ;

    $(DIV)
     .append( $(SPAN).text("Посл. изменение: ") )
     .append( $(SPAN).text(from_unix_time( res['ok']['ts'], false, 'н.д.' )) )
     .append( $(SPAN).addClass("min1em") )
     .append( res['ok']['fk_u_id'] === null?$(SPAN):$(SPAN)
       .text(
         g_data['aux_userinfo'][ res['ok']['fk_u_id'] ]['u_name']+" ("+
         g_data['aux_userinfo'][ res['ok']['fk_u_id'] ]['u_login']+")"
       )
     )
     .appendTo( dialog )
    ;

    $(DIV)
     .append( $(SPAN).text("Диапазон: ") )
     .append( $(INPUT)
       .prop({"id": "r_start", "placeholder": res['ok']['vr_start'], "readonly": !allow_edit})
       .val(res['ok']['vr_start'])
     )
     .append( $(SPAN).text(" - ") )
     .append( $(INPUT)
       .prop({"id": "r_stop", "placeholder": res['ok']['vr_stop'], "readonly": !allow_edit})
       .val(res['ok']['vr_stop'])
     )
     .appendTo( dialog )
    ;

    $(DIV)
     .append( $(SPAN).text("Название: ") )
     .append( $(INPUT)
       .prop({"id": "r_name", "readonly": !allow_edit})
       .val(res['ok']['vr_name'])
     )
     .appendTo( dialog )
    ;

    let css;
    try {
      css = JSON.parse(res['ok']['vr_style']);
    } catch(e) {
      css = g_default_range_style;
    };

    let sample_label;

    sample_label = $(LABEL).addClass("iprange")
     .html('&#x200b;')
     .prop("id", "r_style_sample")
     .css({"width": g_range_bar_width+"px", "margin-right": g_range_bar_width+"px"})
    ;

    $(DIV)
     .append( $(SPAN).html("CSS колонки: ").title("Например: {\"background-color\": \"red\"}") )
     .append( $(INPUT)
       .prop({"id": "r_style", "readonly": !allow_edit})
       .val(res['ok']['vr_style'])
       .on("input change keyup", function() {
         let j = $(this).val();
         try {
           css = JSON.parse(j);
           $("#r_style_sample").css(css);
           $("#r_style_error").hide();
           $(this).css("background-color", "white");
         } catch(e) {
           $("#r_style_error").show();
           $(this).css("background-color", "lightcoral");
         };
       })
     )
     .append( $(SPAN).addClass("min1em") )
     .append( $(SPAN)
       .css({"position": "relative"})
       .append( sample_label )
     )
     .append( $(SPAN)
       .css({"padding-left": g_range_bar_width+g_range_bar_width+2+"px"})
       .append( $(LABEL)
         .prop("id", "r_style_error")
         .addClass(["ui-icon", "ui-icon-alert"])
         .css({"color": "red"})
         .title("Неверный JSON стиля")
         .hide()
       )
     )
     .appendTo( dialog )
    ;

    $(DIV)
     .append( $(A)
       .prop({"href": "https://mkkeck.github.io/jquery-ui-iconfont/#icons", "target": "_blank"})
       .dotted("Выбрать можно тут")
       .text("Значек диапазона ui-icon-*: ")
     )
     .append( $(INPUT)
       .prop({"id": "r_icon", "readonly": !allow_edit})
       .val(res['ok']['vr_icon'])
       .on("input change keyup", function() {
         let v = $(this).val();
         let j = $("#r_icon_style").val();
         let css;
         try {
           css = JSON.parse(j);
           $("#r_icon_style").css("background-color", "white");
           $("#r_icon_style_error").hide();
         } catch(e) {
           $("#r_icon_style").css("background-color", "lightcoral");
           $("#r_icon_style_error").show();
           css = g_default_range_icon_style;
         };
         if(!String(v).match(/^ui-icon-[\-a-z0-9]+$/)) {
           $("#r_icon").css("background-color", "lightcoral");
           $("#r_icon_error").show();
           $("#r_icon_span").empty();
         } else {
           $("#r_icon").css("background-color", "white");
           $("#r_icon_error").hide();
           $("#r_icon_span")
            .empty()
            .append( $(LABEL)
              .addClass(["ui-icon", v])
              .css(css)
            )
           ;
         };
       })
     )
     .append( $(SPAN).addClass("min1em") )
     .append( $(SPAN)
       .prop("id", "r_icon_span")
     )
     .append( $(SPAN).addClass("min1em") )
     .append( $(SPAN)
       .append( $(LABEL)
         .prop("id", "r_icon_error")
         .addClass(["ui-icon", "ui-icon-alert"])
         .css({"color": "red"})
         .title("Неверный класс значка. Должен начинаться на ui-icon-")
         .hide()
       )
     )
     .appendTo( dialog )
    ;

    $(DIV)
     .append( $(SPAN).text("CSS значка диапазона: ").title("Например: {\"color\": \"red\"}") )
     .append( $(INPUT)
       .prop({"id": "r_icon_style", "readonly": !allow_edit})
       .val(res['ok']['vr_icon_style'])
       .on("input change keyup", function() {
         $("#r_icon").trigger("input");
       })
     )
     .append( $(SPAN).addClass("min1em") )
     .append( $(SPAN)
       .append( $(LABEL)
         .prop("id", "r_icon_style_error")
         .addClass(["ui-icon", "ui-icon-alert"])
         .css({"color": "red"})
         .title("Неверный JSON значка")
         .hide()
       )
     )
     .appendTo( dialog )
    ;

    $(DIV)
     .append( $(SPAN).text("Описание: ").css("vertical-align", "top") )
     .append( $(TEXTAREA)
       .prop({"id": "r_descr", "readonly": !allow_edit})
       .val(res['ok']['vr_descr'])
     )
     .appendTo( dialog )
    ;

    $(DIV).text("Права доступа:")
     .css({"margin-top": "0.5em", "margin-bottom": "0.5em"})
     .appendTo( dialog )
    ;

    let table = $(DIV).addClass("table")
     .appendTo(dialog)
    ;

    let not_in_list = [];

    let k_a = keys(res['ok']['groups']);
    sort_by_string_key(k_a, res['ok']['groups'], 'g_name');

    for(let i in k_a) {
      let g_id = k_a[i];
      if(res['ok']['groups'][g_id]['rights'] == 0) {
        not_in_list.push(g_id);
        continue;
      };
      table.append( rights_row("vlan_range", object_id, res['ok']['groups'][g_id], allow_edit) );
    };

    if(allow_edit) {
      let last_row = $(DIV).addClass("tr");

      let select = $(SELECT)
       .append( $(OPTION).text("Выберете группу...").val(0) )
       .val(0)
       .tooltip({
         classes: { "ui-tooltip": "ui-corner-all ui-widget-shadow wsp tooltip" },
         items: "SELECT",
         content: function() {
           return $(this).find("OPTION:selected").prop("title");
         }
       })
      ;

      for(let i in not_in_list) {
        let g_id = not_in_list[i];
        select
         .append( $(OPTION)
           .text(res['ok']['groups'][g_id]['g_name'])
           .title(res['ok']['groups'][g_id]['g_descr'])
           .val(g_id)
         )
        ;
      };

      last_row
       .append( $(SPAN).addClass("td")
         .append( select )
       )
      ;

      last_row
       .append( rights_tds("vlan_range", 0, true) )
      ;

      last_row
       .append( $(SPAN).addClass("td")
         .append( $(LABEL).addClass(["button", "ui-icon", "ui-icon-plus"])
           .click(function() {
             let dialog = $(this).closest(".dialog_start");
             let select = dialog.find("SELECT");
             let option = select.find(":selected");
             let tr = $(this).closest(".tr");
             let g_id = select.val();
             if(g_id == 0) return;

             let this_rights = 0;

             tr.find(".right").each(function() {
               if( $(this).hasClass("right_on") ) {
                 this_rights = this_rights | $(this).data("right");
                 $(this).removeClass("right_on").addClass("right_off");
               };
             });

             if(this_rights == 0) return;

             let new_g_data = dialog.data("groups")[g_id];
             new_g_data['_new'] = true;
             new_g_data['rights'] = this_rights;
             let new_row = rights_row("vlan_range", dialog.data("object_id"),
               new_g_data, true
             );
             new_row.insertBefore(tr);
             option.remove();
           })
         )
       )
      ;

      table.append( last_row );
    };

    let buttons = [];

    if(allow_edit && object_id !== undefined) {
      buttons.push({
        'class': 'left_dlg_button',
        'text': 'Удалить',
        'click': function() {
          let dlg = $(this);

          show_confirm("Подтвердите удаление диапазона.\nВнимание: отмена операции будет невозможна!", function() {
            run_query({"action": "del_vdom_range", "object_id": String(dlg.data("object_id"))}, function(res) {

              dlg.dialog( "close" );

              window.location = "?action=view_vlan_domain&id="+g_data['vd_id']+(DEBUG?"&debug":"");
              return;
            });
          });
        },
      });
    };

    if(allow_edit) {
      buttons.push({
        'text': object_id===undefined?'Создать':'Сохранить',
        'click': function() {
          let dlg = $(this);

          let rights = {};

          if(dlg.find("SELECT").val() != 0 &&
            dlg.find("SELECT").closest(".tr").find(".right_on").length > 0
          ) {
            dlg.find("SELECT").closest(".tr").animateHighlight("lightcoral", 200);
            return;
          };

          dlg.find(".rights_row").each(function() {
            let this_rights = 0;
            $(this).find(".right").each(function() {
              if($(this).hasClass("right_on")) {
                let right = $(this).data("right");
                this_rights |= right;
              };
            });
            if(this_rights > 0) {
              let group = $(this).data("group");
              rights[ group['g_id'] ] = String(this_rights);
            };
          });

          let r_start = $("#r_start").val();
          if(!String(r_start).match(/^\d+$/)) {
            $("#r_start").animateHighlight("red", 300);
            return;
          };

          let r_stop = $("#r_stop").val();
          if(!String(r_stop).match(/^\d+$/)) {
            $("#r_stop").animateHighlight("red", 300);
            return;
          };

          if(Number(r_stop) < Number(r_start)) {
            $("#r_start,#r_stop").animateHighlight("red", 300);
            return;
          };

          if(Number(r_start) < 1) {
            $("#r_start").animateHighlight("red", 300);
            return;
          };
          if(Number(r_stop) > Number(g_data['vd_max_num'])) {
            $("#r_stop").animateHighlight("red", 300);
            return;
          };

          try {
            JSON.parse(String($("#r_style").val()).trim());
          } catch(e) {
            $("#r_style").animateHighlight("red", 300);
            return;
          };

          try {
            JSON.parse(String($("#r_icon_style").val()).trim());
          } catch(e) {
            $("#r_icon_style").animateHighlight("red", 300);
            return;
          };

          if(!String($("#r_icon").val()).trim().match(/^ui-icon-[\-a-z0-9]+$/)) {
            $("#r_icon").animateHighlight("red", 300);
            return;
          };

          let query = {
            "action": "save_vdom_range",
            "object_id": dlg.data("object_id")===undefined?"":dlg.data("object_id"),
            "vd_id": String(g_data['vd_id']),
            "rights": rights,
            "r_start": String(r_start),
            "r_stop": String(r_stop),
            "r_name": String($("#r_name").val()).trim(),
            "r_descr": String($("#r_descr").val()).trim(),
            "r_style": String($("#r_style").val()).trim(),
            "r_icon": String($("#r_icon").val()).trim(),
            "r_icon_style": String($("#r_icon_style").val()).trim(),
          };
          run_query(query, function(res) {
            dlg.dialog( "close" );

            window.location = "?action=view_vlan_domain&id="+g_data['vd_id']+(DEBUG?"&debug":"");
            return;
          });
        },
      });
    };

    buttons.push({
      'text': allow_edit?'Отмена':'Закрыть',
      'click': function() {$(this).dialog( "close" );},
    });

    let dialog_options = {
      modal:true,
      maxHeight:1000,
      maxWidth:1800,
      minWidth:1200,
      width: "auto",
      height: "auto",
      buttons: buttons,
      close: function() {
        $(this).dialog("destroy");
        $(this).remove();
      }
    };

    dialog.appendTo("BODY");
    dialog.dialog( dialog_options );

    $("#r_style").trigger("input");
    $("#r_icon").trigger("input");
  });
};

function select_vlan(pre_vlan_data, donefunc) {
  run_query({"action": "list_vlan_domains"}, function(res) {
    if(res['ok']['aux_userinfo'] !== undefined) {
      if(g_data['aux_userinfo'] === undefined) g_data['aux_userinfo'] = {};
      for(let u_id in res['ok']['aux_userinfo']) {
        g_data['aux_userinfo'][u_id] = res['ok']['aux_userinfo'][u_id];
      };
    };

    let dlg = $(DIV).addClass("dialog_start")
     .title("Выбор VLAN")
     .data("pre_vlan_data", pre_vlan_data)
     .data("donefunc", donefunc)
    ;

    let vd_sel = $(SELECT).addClass("vd_id")
     .append( $(OPTION).text("Выберите домен...")
       .val("0")
     )
     .append( $(OPTION).text("Убрать назначение VLAN")
       .val("")
     )
     .tooltip({
       classes: { "ui-tooltip": "ui-corner-all ui-widget-shadow wsp tooltip" },
       items: "SELECT",
       content: function() {
         return $(this).find("OPTION:selected").prop("title");
       },
     })
    ;

    for(let i in res['ok']['vds']) {
      vd_sel
       .append( $(OPTION).text(res['ok']['vds'][i]['vd_name'])
         .title(res['ok']['vds'][i]['vd_descr'])
         .val(res['ok']['vds'][i]['vd_id'])
       )
      ;
    };

    if(pre_vlan_data !== undefined && pre_vlan_data['vlan_fk_vd_id'] !== undefined) {
      vd_sel.val(pre_vlan_data['vlan_fk_vd_id']);
    } else {
      vd_sel.val("0");
    };

    vd_sel
     .on("change", function() {
       let val = $(this).val();
       let dlg = $(this).closest(".dialog_start");

       if(val === "0" || val === "") {
         dlg.find(".vlan_id").empty()
          .append( $(OPTION).text("Домен не выбран").val("0") )
          .append( $(OPTION).text("Убрать назначение VLAN").val("") )
         ;
         dlg.find(".vlan_id").val(val);
         return;
       };

       run_query({"action": "view_vlan_domain", "id": String(val)}, function(res) {
         let sel = dlg.find(".vlan_id");
         sel.empty()
          .append( $(OPTION).text("Выберите VLAN...").val("0") )
          .append( $(OPTION).text("Убрать назначение VLAN").val("") )
         ;

         let pre_data = dlg.data("pre_vlan_data");

         let presel = "0";

         for(let vlan_i in res['ok']['vlans']) {
           if(res['ok']['vlans'][vlan_i]['is_taken'] !== undefined) {
             sel
              .append( $(OPTION)
                .text(String(res['ok']['vlans'][vlan_i]['vlan_number'])+" "+String(res['ok']['vlans'][vlan_i]['vlan_name']))
                .title(res['ok']['vlans'][vlan_i]['vlan_descr'])
                .val(res['ok']['vlans'][vlan_i]['vlan_id'])
                .data("vlan_data", res['ok']['vlans'][vlan_i])
              )
             ;
             if(pre_data !== undefined && pre_data['vlan_id'] == res['ok']['vlans'][vlan_i]['vlan_id']) {
               presel = pre_data['vlan_id'];
             };
           };
         };

         sel.val(presel);
       });
     })
    ;

    dlg
     .append( $(DIV)
       .append( vd_sel )
     )
     .append( $(DIV)
       .append( $(SELECT).addClass("vlan_id") )
     )
    ;

    let buttons = [];

    buttons.push({
      'text': 'Выбрать',
      'click': function() {
        let dlg = $(this);
        let donefunc = dlg.data("donefunc");

        let val = dlg.find(".vlan_id").val();

        if(val === "0") return;

        if(donefunc !== undefined) {
          let data = {"vlan_id": ""};
          if(val !== "") {
            data = dlg.find(".vlan_id").find("OPTION:selected").data("vlan_data");
            data["vd_name"] = dlg.find(".vd_id").find("OPTION:selected").text();
          };
          dlg.dialog( "close" );
          donefunc(data);
        };
      },
    });

    buttons.push({
      'text': 'Отмена',
      'click': function() {$(this).dialog( "close" );},
    });

    let dialog_options = {
      modal:true,
      maxHeight:1000,
      maxWidth:1800,
      minWidth:1200,
      width: "auto",
      height: "auto",
      buttons: buttons,
      close: function() {
        $(this).dialog("destroy");
        $(this).remove();
      }
    };

    dlg.appendTo("BODY");
    dlg.dialog( dialog_options );

    dlg.find(".vd_id").trigger("change");

  });
};

function vlan_label(object, object_id, vlan_data, allow_edit = false, prefix = "", not_set = "") {
  let ret = $(LABEL)
   .addClass("vlan")
   .addClass("unsaved_elm")
   .data("object", object)
   .data("object_id", object_id)
   .data("vlan_data", vlan_data)
   .data("allow_edit", allow_edit)
   .data("prefix", prefix)
   .data("not_set", not_set)
  ;
  if(vlan_data !== undefined && vlan_data["vlan_id"] !== undefined && vlan_data["vlan_id"] !== "") {
    ret
     .append( $(SPAN)
       .addClass("vlan_label")
       .css(g_vlan_css)
       .text( prefix+String(vlan_data['vlan_number']) )
       .tooltip({
         classes: { "ui-tooltip": "ui-corner-all ui-widget-shadow wsp tooltip" },
         items: "LABEL",
         content: function() {
           let vlan_data = $(this).data('vlan_data');
          
           let ret = $(DIV)
            .append( $(DIV)
              .append( $(SPAN).text("VLAN: "+vlan_data['vlan_number']) )
            )
            .append( $(DIV)
              .append( $(SPAN).text("Домен: "+vlan_data['vd_name']) )
            )
            .append( $(DIV)
              .append( $(SPAN).text("Имя: "+vlan_data['vlan_name']) )
            )
           ;
           return ret;
         }
       })
     )
    ;
  } else {
    ret
     .append( $(SPAN)
       .addClass("vlan_label")
       .css(g_vlan_css)
       .text(not_set)
       .toggle(not_set != "")
     )
    ;
  };

  if(allow_edit) {
    ret
     .append( $(INPUT)
       .prop({"type": "hidden"})
       .val(vlan_data === undefined?"":vlan_data["vlan_id"])
       .saveable({
         "object": object,
         "id": object_id,
         "prop": "vlan"
       })
     )
     .on("click dblclick", function(e) {
       if ((e.type == "click" && e.ctrlKey) ||
           e.type == "dblclick"
       ) {
         e.stopPropagation();
         $(this).trigger("set");
       };
     })
     .on("set", function() {
       let elm = $(this);
       let object = elm.data("object");
       let vlan_data = elm.data("vlan_data");
       let allow_edit = elm.data("allow_edit");
       let prefix = elm.data("prefix");
       let not_set = elm.data("not_set");

       select_vlan(vlan_data, function(new_data) {
         elm.find("INPUT[type=hidden]").val(new_data["vlan_id"]);
         elm.data("vlan_data", new_data);
         elm.find(".vlan_label").show();
         if(new_data["vlan_id"] != "") {
           elm.find(".vlan_label")
            .text(String(prefix)+String(new_data["vlan_number"]))
           ;
         } else {
           elm.find(".vlan_label").text(not_set);
         };

         elm.find("INPUT[type=hidden]").trigger("input_stop");
       })
     })
    ;
  };

  return ret;
};
