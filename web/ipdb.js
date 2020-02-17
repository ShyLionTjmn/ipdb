// GLOBALS

var ud;
var $R={};
var page_root;


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


function v4_global_range_dialog(v4r_id, donefunc) {
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
   .addClass("dialog_start")
   .prop("title", title)
   .css("white-space", "pre")
   .appendTo("BODY")
  ;

  let d={
    modal:false,
    maxHeight:1000,
    maxWidth:1000,
    minWidth:600,
    buttons: [],
    close: function() {
      $(".range_btn").hide();
      $(this).dialog("destroy");
      $(this).remove();
    }
  };

  d['buttons'].push({ "text": (donefunc != undefined)?"Отмена":"Закрыть", "click": function() {$(this).dialog( "close" ); } });

  let table=$(TABLE);

  table
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Начало:") )
     )
     .append( $(TD)
       .append( $(INPUT).id("v4range_start").prop({"placeholder": "x.x.x.x"})
         .on("change input", validate_v4range)
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Окончание:") )
     )
     .append( $(TD)
       .append( $(INPUT).id("v4range_stop").prop({"placeholder": "x.x.x.x"})
         .on("change input", validate_v4range)
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Наименование:") )
     )
     .append( $(TD)
       .append( $(INPUT).id("v4range_name").prop({"placeholder": "Краткое наименование"})
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Описание:") )
     )
     .append( $(TD)
       .append( $(TEXTAREA).id("v4range_descr")
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Скрытый:") )
     )
     .append( $(TD)
       .append( $(INPUT).id("v4range_invisible").prop({"type": "checkbox"})
       )
     )
   )
   .append( $(TR)
     .append( $(TD).css({"text-align": "right"})
       .append( $(LABEL).text("Стиль (JSON):") )
     )
     .append( $(TD)
       .append( $(INPUT).id("v4range_style").prop({"placeholder": "JSON строка для .css()"})
         .on("change input", validate_json)
       )
     )
   )
  ;

  table.appendTo( dialog );

  dialog.dialog(d);

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
    } else if(String(ranges[r]['v4r_icon']).match(/^&#[0-9a-fA-F]+;$/)) {
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
    row.appendTo( table_div );
  };
  table_div.appendTo( calc_cont );
  $("#calc").show();
};

function v4calc_show(net, masklen, elm) {
  clear_calc();

  let calc_text="Network: "+v4long2ip(net)+"/"+masklen;
  calc_text += "\nMask: "+v4long2ip(v4len2mask[masklen]);
  calc_text += "\nWildcard: "+ v4long2ip( (~v4len2mask[masklen]) >>> 0);
  calc_text += "\nLast IP: "+v4long2ip((net | ~v4len2mask[masklen]) >>> 0);

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

  let table=$(TABLE)
   .css({"border-collapse": "collapse", "font-size": "large", "border": "1px solid #222222"})
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
   .css({"position": "sticky", "top": "0", "background-color": "white", "z-index": 1000000, "border-bottom": "1px solid gray", "padding-left": "0.2em"})
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
         $R={"action": "v4get_net", "net": _net, "masklen": _masklen};
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
       $R={"action": "v4get_net", "net": _net, "masklen": _masklen};
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

  for(let cur_masklen=masklen_start; cur_masklen <= masklen_stop; cur_masklen++) {
    $(TH).text("/"+cur_masklen)
     .css({"position": "sticky", "top": "0", "background-color": "white", "z-index": 1000000, "border-bottom": "1px solid gray", "border-left": "1px solid gray"})
     .appendTo(htr)
    ;
  };

  //net name column
  $(TH)
   .css({"position": "sticky", "top": "0", "background-color": "white", "z-index": 1000000, "border-bottom": "1px solid gray", "border-left": "1px solid gray"})
   .appendTo(htr)
  ;

  //ranges column
  let r_th=$(TH)
   .css({"position": "sticky", "top": "0", "background-color": "white", "z-index": 1000000, "border-bottom": "1px solid gray", "border-left": "1px solid gray"})
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

    let row_has_nets=false;

    for(n in data['nets']) {
      if(row_net >= data['nets'][n]['v4net_addr'] && row_net <= data['nets'][n]['v4net_last']) {
        row_has_nets=true;
        break;
      };
    };

    if(data['aggr_nets'][ row_net ] != undefined) {
      row_has_nets=true;
    };

    let tr=$(TR).data('has_nets', row_has_nets);
    if(!row_has_nets) tr.addClass("has_no_nets");

    if(o % 2) {
      tr.css({"background-color": color_odd});
    } else {
      tr.css({"background-color": color_even});
    };

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
             .hide()
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
             .hide()
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
               $R={"action": "v4get_net", "net": _net, "masklen": _masklen};
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


    tr.appendTo(tbody);
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
             $R={ "action": "v4get_net", "net": 0, "masklen": 0 };
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

        process_R();

      };

    };
  });

});
