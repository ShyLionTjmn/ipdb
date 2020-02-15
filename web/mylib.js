const DIV="<DIV/>";
const IMG="<IMG/>";
const SPAN="<SPAN/>";
const LABEL="<LABEL/>";
const TABLE="<TABLE/>";
const THEAD="<THEAD/>";
const TBODY="<TBODY/>";
const TFOOT="<TFOOT/>";
const TR="<TR/>";
const TH="<TH/>";
const TD="<TD/>";
const INPUT="<INPUT/>";
const SELECT="<SELECT/>";
const OPTION="<OPTION/>";
const BR="<BR/>";
const A="<A/>";
const FORM="<FORM/>";
const TEXTAREA="<TEXTAREA/>";
const BUTTON="<BUTTON/>";

let notLocked = true;
$.fn.animateHighlight = function(highlightColor, duration) {
    let highlightBg = highlightColor || "#FF4444";
    let animateMs = duration || 1500;
    let originalBg = this.css("backgroundColor");
    if (notLocked) {
        notLocked = false;
        this.stop().css("background-color", highlightBg)
            .animate({backgroundColor: originalBg}, animateMs);
        setTimeout( function() { notLocked = true; }, animateMs);
    }
};

$.fn.enterKey = function (fnc) {
    return this.each(function () {
        $(this).keypress(function (ev) {
            let keycode = (ev.keyCode ? ev.keyCode : ev.which);
            if (keycode == '13') {
                fnc.call(this, ev);
            }
        })
    })
};

// triggers input_stop event on input stop after timeout
$.fn.inputStop = function (timeout) {
  $(this)
   .data("input_stop_timeout", timeout)
   .on("input", function() {
     let t=$(this).data("input_stop_timer");
     if(t !== undefined) clearTimeout(t);
     let to=$(this).data("input_stop_timeout");

     let th=$(this);
     $(this).data("input_stop_timer", setTimeout(function() {
       th.data("input_stop_timer", undefined);
       th.trigger("input_stop");
     }, to));
   })
   .on("keydown", function() {
     let t=$(this).data("input_stop_timer");
     if(t !== undefined) clearTimeout(t);
   })
  ;
  return $(this);
};

$.fn.title = function(title) {
  $(this).prop("title", title)
   .css({"text-decoration": "none"});
  return this;
};

$.fn.id = function(idstring) {
  $(this).prop("id", idstring);
  return this;
};

$.fn.dotted = function(title) {
  $(this).prop("title", title)
   .css({"text-decoration-style": "dotted", "text-decoration-line": "underline"});
  return this;
};

RegExp.escape= function(s) {
    return s.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
};

function dup(obj) { return $.extend(true, {}, obj); };

function keys(obj) {
  let keys = [];

  for(let key in obj) {
    if(obj.hasOwnProperty(key)) {
      keys.push(key);
    };
  };

  return keys;
};

function ln() {
  let e = new Error();
  if (!e.stack) try {
    // IE requires the Error to actually be throw or else the Error's 'stack'
    // property is undefined.
    throw e;
  } catch (e) {
    if (!e.stack) {
      return 0; // IE < 10, likely
    }
  }
  let stack = e.stack.toString().split(/\r\n|\n/);
  // We want our caller's frame. It's index into |stack| depends on the
  // browser and browser version, so we need to search for the second frame:
  let frameRE = /:(\d+):(?:\d+)[^\d]*$/;
  do {
    let frame = stack.shift();
  } while (!frameRE.exec(frame) && stack.length);
  return frameRE.exec(stack.shift())[1];
};

function addZero(num) {
  if(num > 9) return num.toString();
  return "0"+num.toString();
};

function unix_timestamp(date) {
  if(date === undefined) date=new Date();
  return Math.round(date.getTime()/1000);
};

function from_unix_time(timestamp, relative, never) {
  if(timestamp == 0) return (never==undefined)?"нет":never;
  let now=new Date();

  let date=new Date(timestamp*1000);
  let year=date.getFullYear();
  let month=addZero(date.getMonth()+1);
  let day=addZero(date.getDate());

  let hours=addZero(date.getHours());
  let minutes=addZero(date.getMinutes());
  let seconds=addZero(date.getSeconds());

  let ret_abs=year+"."+month+"."+day+" "+hours+":"+minutes+":"+seconds;
  let ret_today=hours+":"+minutes+":"+seconds;

  if(relative &&
     now.getDate()==date.getDate() &&
     now.getMonth()==date.getMonth() &&
     now.getFullYear()==date.getFullYear()
  ) {
    return ret_today;
  } else {
    return ret_abs;
  };
};

function jstr(obj) {
  return JSON.stringify(obj, null, 2);
};

function error_dialog(message, opts) {
  let dialog=$(DIV).prop("title", "Ошибка")
                   .css("white-space", "pre")
                   .text(message)
                   .appendTo("BODY");
  let d={
    modal:true,
    maxHeight:1000,
    maxWidth:1000,
    minWidth:600,
    buttons: { "Закрыть": function() {$(this).dialog( "close" );} },
    close: function() {
      $(this).dialog("destroy");
      $(this).remove();
    }
  };
  if(opts != undefined) {
    for(let o in opts) {
      d[o]=opts[o];
    };
  };
  dialog.dialog(d);
  dialog.addClass("ui-state-error");
  $("#led").css("background-color", "lightcoral");
};

function show_dialog(message, opts) {
  let dialog=$(DIV).prop("title", "Сообщение").css("white-space", "pre").text(message).appendTo("BODY");
  let d={
    modal:true,
    maxHeight:800,
    maxWidth:1500,
    minWidth:600,
    buttons: { "Закрыть": function() {$(this).dialog( "close" );} },
    close: function() {
      $(this).dialog("destroy");
      $(this).remove();
    }
  };
  if(opts != undefined) {
    for(let o in opts) {
      d[o]=opts[o];
    };
  };
  dialog.dialog(d);
};

function show_confirm(message,func, opts, cancelfunc) {
  let dialog=$(DIV).data("done", 0).prop("title", "Подтвердите действие").css("white-space", "pre").text(message).appendTo("BODY");
  let d={
    modal:true,
    maxHeight:1000,
    maxWidth:1000,
    minWidth:600,
    buttons: {
      "Отменить": function() {$(this).dialog( "close" );},
      "Выполнить": function() { $(this).data("done", 1); $(this).dialog( "close" ); func(); },
    },
    close: function() {
      let done=$(this).data("done");
      $(this).dialog("destroy");
      $(this).remove();
      if(cancelfunc !== undefined && done == 0) { cancelfunc(); };
    }
  };
  if(opts != undefined) {
    for(let o in opts) {
      d[o]=opts[o];
    };
  };
  dialog.dialog(d);
};

function show_confirm_checkbox(message,func, opts) {
  let dialog=$(DIV)
   .prop("title", "Подтвердите действие")
   .css("white-space", "pre")
   .text(message)
   .append($(BR))
   .append($(BR))
   .append( $(LABEL).text("Я все внимательно прочел и подтверждаю действие: ") )
   .append( $(INPUT).prop("type", "checkbox") )
   .appendTo("BODY")
  ;
  let d={
    modal:true,
    maxHeight:1000,
    maxWidth:1000,
    minWidth:600,
    buttons: {
      "Отменить": function() {$(this).dialog( "close" );},
      "Выполнить": function() {
        if(!$(this).find("INPUT").is(":checked")) return;
        $(this).dialog( "close" );
        func();
      },
    },
    close: function() {
      $(this).dialog("destroy");
      $(this).remove();
    }
  };
  if(opts != undefined) {
    for(let o in opts) {
      d[o]=opts[o];
    };
  };
  dialog.dialog(d);
};

function showLoginWindow(prov_list, message) {
  let dialog=$(DIV).addClass("dialog_start")
   .title("Вход")
   .appendTo("BODY")
  ;

  if(message !== undefined) {
    dialog.append( $(DIV).text(message).css({"text-size": "x-large"}) );
  };

  for(i in prov_list) {
    let prov=prov_list[i];

    let ipdb_uri=window.location.href.split("/").slice(0, -1).join("/") + "/";

    let login_uri=ipdb_uri + "login.php";
    login_uri = uri_add_param(login_uri, "ap_id", prov["ap_id"]);
    login_uri = uri_add_param(login_uri, "ipdb_uri", ipdb_uri);
    login_uri = uri_add_param(login_uri, "success_uri", window.location.href);

    let prov_div=$(DIV)
     .css({"display": "inline-block", "margin": "1em", "border": "2px solid gray", "padding": "1em"})
     .append( $(A).prop({"href": login_uri}).title(prov["ap_name"])
       .append( $(IMG).prop("src", prov["ap_icon"]) )
     )
     .appendTo(dialog)
    ;

  };

  let d={
    modal: true,
    minWidth: 300,
    closeOnEscape: false,
    open: function() {
      $(this).closest(".ui-dialog").find(".ui-dialog-titlebar-close").hide();
    },
    close: function() {
      $(this).dialog("destroy");
      $(this).remove();
    }
  };

  dialog.dialog(d);
};


function run_query(query, successfunc) {
  if(AJAX == undefined) {
    error_dialog("AJAX uri not set");
    return;
  };
  $("#led").css("background-color", "yellow");
  $.ajax({
    url: AJAX,
    method: 'POST',
    dataType: "json",
    contentType: 'application/json',
    processData: false,
    data: JSON.stringify(query),
    success: function(data) {
      if(data["ok"] != undefined) {
        $("#led").css("background-color", "lightgreen");
        if(DEBUG) {
          $("#debug").text(JSON.stringify(data, null, 2));
        };
        if(data["ok"]["no_auth"] != undefined) {
          showLoginWindow(data["no_auth"], "Истекло время неактивности сеанса, необходимо пройти авторизацию.");
          return;
        };
        if(successfunc != null) {
          successfunc(data);
        };
        return;
      };
      let message;
      if(data["error"] != undefined) {
        if(typeof(data["error"]) === "string") {
          message=data["error"];
        } else {
          message=JSON.stringify(data["error"], null, 2);
        };
      } else {
        message=JSON.stringify(data, null, 2);
      };
      error_dialog(message);
      $("#led").css("background-color", "lightcoral");
    },
    error: function(e) {
      error_dialog("AJAX request error\n"+(e.responseText !== undefined? e.responseText:""));
      $("#led").css("background-color", "lightcoral");
    }
  });
};

function uri_add_param(uri, param, value) {
  let ret=uri;

  if(String(ret).indexOf("?") >= 0) {
    ret += "&"+param;
  } else {
    ret += "?"+param;
  };

  if(value !== undefined) {
    ret += "="+encodeURIComponent(value);
  };

  return ret;
};

function error_at(message) {
  let e = new Error();
  if (!e.stack) try {
    // IE requires the Error to actually be throw or else the Error's 'stack'
    // property is undefined.
    throw e;
  } catch (e) {
    if (!e.stack) {
      return 0; // IE < 10, likely
    }
  }
  let stack = e.stack.toString().split(/\r\n|\n/);
  // We want our caller's frame. It's index into |stack| depends on the
  // browser and browser version, so we need to search for the second frame:
  let frameRE = /:(\d+):(?:\d+)[^\d]*$/;
  do {
    var frame = stack.shift();
  } while (!frameRE.exec(frame) && stack.length);

  if(message === undefined) message="Program error";
  let line=frameRE.exec(stack.shift())[1];
  error_dialog(message+" at "+line);
};

function nets2lang(capital, lang, num) {
  let ret;
  if(lang == "ru") {
    if(capital) { ret="С"; } else { ret="с"; };
    let strnum=String(num);

    if(strnum.match(/1$/) && num != 11) {
      ret += "еть";
    } else if(strnum.match(/[2-4]$/) && (num < 12 || num > 14)) {
      ret += "ети";
    } else {
      ret += "етей";
    };

  } else {
    if(capital) { ret="N"; } else { ret="n"; };
    if(num != 1) {
      ret += "ets";
    } else {
      ret += "et";
    };
  };
  return ret;
};

function ranges2lang(capital, lang, num) {
  let ret;
  if(lang == "ru") {
    if(capital) { ret="Д"; } else { ret="д"; };
    let strnum=String(num);

    if(strnum.match(/1$/) && num != 11) {
      ret += "иапазон";
    } else if(strnum.match(/[2-4]$/) && (num < 12 || num > 14)) {
      ret += "иапазона";
    } else {
      ret += "иапазонов";
    };

  } else {
    if(capital) { ret="R"; } else { ret="r"; };
    if(num != 1) {
      ret += "anges";
    } else {
      ret += "ange";
    };
  };
  return ret;
};
function param_by_type_check(type, value) {
  if(type == "v4long") {
    if(!String(value).match(/^\d+$/) || Number(value) < 0 || Number(value) > 4294967295) return false;
  } else if(type == "v4masklen") {
    if(!String(value).match(/^\d+$/) || Number(value) < 0 || Number(value) > 32) return false;
  } else {
    return false;
  };

  return true;
};

function require_param(key, check) {
  if($R[key] === undefined) {
    error_dialog("Required param "+key+" is missing");
    throw("Required param "+key+" is missing");
  };
  if(check == undefined) return true;
  if(typeof(check) === "object") {
    if(typeof($R[key]) === "object") {
      for(let i in $R[key]) {
        if(!String($R[key][i]).match(check)) {
          error_dialog("Required param "+key+" has bad value "+String($R[key][i]));
          throw("Required param "+key+" has bad value "+String($R[key][i]));
        };
      };
    } else if(!String($R[key]).match(check)) {
      error_dialog("Required param "+key+" has bad value "+String($R[key]));
      throw("Required param "+key+" has bad value "+String($R[key]));
    };
  } else {
    if(typeof($R[key]) === "object") {
      for(let i in $R[key]) {
        if(!param_by_type_check(check, $R[key][i])) {
          error_dialog("Required param "+key+" has bad value "+String($R[key][i]));
          throw("Required param "+key+" has bad value "+String($R[key][i]));
        };
      };
    } else if(!param_by_type_check(check, $R[key])) {
      error_dialog("Required param "+key+" has bad value "+String($R[key]));
      throw("Required param "+key+" has bad value "+String($R[key]));
    };
  };
};
