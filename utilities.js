// JavaScript Utilities
// Copyright (C) 2014-2017 Bernhard Waldbrunner
/*
*	This program is free software: you can redistribute it and/or modify
*	it under the terms of the GNU General Public License as published by
*	the Free Software Foundation, either version 3 of the License, or
*	(at your option) any later version.
*
*	This program is distributed in the hope that it will be useful,
*	but WITHOUT ANY WARRANTY; without even the implied warranty of
*	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*	GNU General Public License for more details.
*
*	You should have received a copy of the GNU General Public License
*	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

(function() {
	"use strict";

	if (!Function.prototype.method) {
		Function.prototype.method = function(name, func) {
			if (!this.prototype[name]) {
				this.prototype[name] = func;
			}
			return this;
		};
	}

	Function.method('curry', function() {
		var slice = Array.prototype.slice, args = slice.apply(arguments), that = this;
		return function () {
			return that.apply(null, args.concat(slice.apply(arguments)));
		};
	});

	Object.method('superior', function(name) {
		var that = this, method = that[name];
		return function () {
			return method.apply(that, arguments);
		};
	});

	if (!Object.create) {
		Object.create = function (o) {
			var F = function () {};
			F.prototype = o;
			return new F();
		};
	}

	function extend(props, override) {
		var key;
		for (key in props) {
			if (override || !(key in this)) {
				this[key] = props[key];
			}
		}
		return this;
	}

	Object.method('extend', extend);

	if (!Array.isArray) {
		Array.isArray = function(obj) {
			return obj && typeof obj == 'object' && typeof obj.length == 'number' &&
			!obj.propertyIsEnumerable('length');
		};
	}

	Array.method('unique', function() {
		return this.reduce(function(a, b) {
			if (a.indexOf(b) < 0) {
				a.push(b);
			}
			return a;
		}, []);
	});

	if (!Number.isNumber) {
		Number.isNumber = function(val) {
			return typeof val == 'number' && isFinite(val);
		};
	}

	if (!Array.copy) {
		Array.copy = function(a) {
			var ary = [], i;
			for (i = a.length >>> 0; i--;) {
				if (Array.isArray(a[i])) {
					ary[i] = Array.copy(a[i]);
				}
				else if (typeof a[i] == 'object') {
					ary[i] = Object.create(a[i]);
				}
				else {
					ary[i] = a[i];
				}
			}
			return ary;
		};
	}

	if (!Array.dim) {
		Array.dim = function(length, initial) {
			var a = [], i, ary = Array.isArray(initial), obj = (typeof initial == 'object');
			for (i = 0; i < length; i++) {
				a[i] = (ary ? initial.copy() : (obj ? Object.create(initial) : initial));
			}
			return a;
		};
	}

	Array.method('reduce', function(f, val) {
		var i;
		for (i = 0; i < this.length; i++) {
			val = f(this[i], val);
		}
		return val;
	});

	if (!RegExp.quote) {
		RegExp.quote = function (str) {
			return str.replace(/[.?*+^$[\]\\(){}|-]/g, "\\$&");
		};
	}

	if (!Object.getKey) {
		Object.getKey = function(obj, val, type, idx) {
			if (typeof obj != "object" || obj == null) {
				return null;
			}
			idx = (typeof idx == "undefined" ? 0 : parseInt(idx));
			var i = 0, k;
			for (k in obj) {
				if ((!type || typeof obj[k] == type) && idx == i++ && val === obj[k]) {
					return k;
				}
			}
			return false;
		};
	}

	var MAIL_RX,
		SCHEME = "[a-z\\d.-]+://",
		IPV4 = "(?:(?:[0-9]|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])\\.){3}(?:[0-9]|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])",
		HOSTNAME = "(?:(?:[^\\s!@#$%^&*()_=+[\\]{}\\\\|;:'\",.<>/?]+)\\.)+",
		TLD = "(?:ac|ad|aero|ae|af|ag|ai|al|am|an|ao|aq|arpa|ar|asia|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|biz|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|cat|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|coop|com|co|cr|cu|cv|cx|cy|cz|de|dj|dk|dm|do|dz|ec|edu|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gov|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|info|int|in|io|iq|ir|is|it|je|jm|jobs|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mil|mk|ml|mm|mn|mobi|mo|mp|mq|mr|ms|mt|museum|mu|mv|mw|mx|my|mz|name|na|nc|net|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|org|pa|pe|pf|pg|ph|pk|pl|pm|pn|pro|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tel|tf|tg|th|tj|tk|tl|tm|tn|to|tp|travel|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|xn--[0-9a-z]+|ye|yt|yu|za|zm|zw)",
		HOST_OR_IP = "(?:" + HOSTNAME + TLD + "|" + IPV4 + ")",
		PATH = "(?:[;/][^#?<>\\s]*)?",
		QUERY_FRAG = "(?:\\?[^#<>\\s]*)?(?:#[^<>\\s]*)?",
		URI1 = "\\b" + SCHEME + "[^<>\\s]+",
		URI2 = "\\b" + HOST_OR_IP + PATH + QUERY_FRAG + "(?!\\w)",
		MAILTO = "mailto:",
		EMAIL = "[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@" + HOST_OR_IP + QUERY_FRAG + "(?!\\w)";
		MAIL_RX = new RegExp("^" + EMAIL + "$", "i");
	EMAIL = "(?:" + MAILTO + ")?" + EMAIL;
	var URI_RE = new RegExp("(?:" + URI1 + "|" + URI2 + "|" + EMAIL + ")", "ig"),
		SCHEME_RE = new RegExp("^" + SCHEME, "i"),
		quotes = {
			"'": "`",
			'>': '<',
			')': '(',
			']': '[',
			'}': '{',
			'\xBB': '\xAB',
			'\u203A': '\u2039'
		},
		default_options = {
			callback: function(text, href) {
				return href ? '<a href="' + href + '" title="' + href + '">' + text + '</a>' : text;
			},
			punct_regexp: /(?:[!?.,:;'"]|(?:&|&amp;)(?:lt|gt|quot|apos|raquo|laquo|rsaquo|lsaquo);)$/
		};

	String.method('linkify', function(options) {
		function replacePunctuation(a) {
			idx_last -= a.length;
			return '';
		}
		options = options || {};
		var txt = this;
		// Temp variables.
		var arr,
			i,
			link,
			href,
			// Output HTML.
			html = '',
			// Store text / link parts, in order, for re-combination.
			parts = [],
			// Used for keeping track of indices in the text.
			idx_prev,
			idx_last,
			idx,
			link_last,
			// Used for trimming trailing punctuation and quotes from links.
			matches_begin,
			matches_end,
			quote_begin,
			quote_end;
		// Initialize options.
		extend.call(options, default_options);

		// Find links.
		while (arr = URI_RE.exec(txt)) {
			link = arr[0];
			idx_last = URI_RE.lastIndex;
			idx = idx_last - link.length;
			// Not a link if preceded by certain characters.
			if (/[\/:]/.test(txt.charAt(idx - 1))) {
				continue;
			}
			// Trim trailing punctuation.
			do {
				// If no changes are made, we don't want to loop forever!
				link_last = link;
				quote_end = link.substr(-1);
				quote_begin = quotes[quote_end];
				// Ending quote character?
				if (quote_begin) {
					matches_begin = link.match(new RegExp('\\' + quote_begin + '(?!$)', 'g'));
					matches_end = link.match(new RegExp('\\' + quote_end, 'g'));

					// If quotes are unbalanced, remove trailing quote character.
					if ((matches_begin ? matches_begin.length : 0) < (matches_end ? matches_end.length : 0)) {
						link = link.substr(0, link.length - 1);
						idx_last--;
					}
				}
				// Ending non-quote punctuation character?
				if (options.punct_regexp) {
					link = link.replace(options.punct_regexp, replacePunctuation);
				}
			}
			while (link.length && link !== link_last);
			href = link;
			// Add appropriate protocol to naked links.
			if (!SCHEME_RE.test(href)) {
				href = (href.indexOf('@') !== -1 ? (!href.indexOf(MAILTO) ? '' : MAILTO)
					: !href.indexOf('irc.') ? 'irc://'
					: !href.indexOf('ftp.') ? 'ftp://'
					: 'http://') + href;
			}
			// Push preceding non-link text onto the array.
			if (idx_prev != idx) {
				parts.push([txt.slice(idx_prev, idx)]);
				idx_prev = idx_last;
			}
			// Push massaged link onto the array
			parts.push([link, href]);
		}
		// Push remaining non-link text onto the array.
		parts.push([txt.substr(idx_prev)]);
		// Process the array items.
		for (i = 0; i < parts.length; i++) {
			html += options.callback.apply(null, parts[i]);
		}
		// In case of catastrophic failure, return the original text;
		return html || txt;
	});

	String.method('isEmail', function () {
		return MAIL_RX.test(this);
	});

	String.method('toURIComponent', function (separator) {
		if (typeof separator == 'undefined') {
			separator = '-';
		}
		var s = this.toLowerCase(), str = '', space = true, start = true;
		for (var i = 0; i < s.length; i++) {
			var c = s.charCodeAt(i);
			// [a-z0-9]
			if ((c >= 97 && c <= 122) || (c >= 48 && c <= 57)) {
				if (space && !start) {
					str += separator;
				}
				str += s.charAt(i);
				space = false;
				start = false;
			}
			// [\s_-]
			else if (c == 95 || c == 32 || c == 45 || c == 9 || c == 10) {
				space = true;
			}
		}
		return str;
	});

	String.method('escape', function () {
		return this.replace(/\\/g, '\\\\')
			.replace(/'/g, "\\'")
			.replace(/"/g, '\\"');
	});

	String.method('unescape', function () {
		return this.replace(/\\\\/g, '\x01/')
			.replace(/\\t/g, "\t")
			.replace(/\\b/g, "\b")
			.replace(/\\f/g, "\f")
			.replace(/\\n/g, "\n")
			.replace(/\\r/g, "\r")
			.replace(/\\v/g, "\v")
			.replace(/\\'/g, "'")
			.replace(/\\"/g, '"')
			.replace(/\x01\//g, "\\");
	});

	if (!window.clearAllTimeouts && !window.resetTimeouts) {
		var _setTimeout = window.setTimeout, _setInterval = window.setInterval;
		var timeouts = [], intervals = [];

		window.setTimeout = function(func) {
			var now = Date.parse(new Date()), i, item, id, updated = [];
			for (i = 0, len = timeouts.length; i < len; i++) {
				item = timeouts[i];
				if (now <= item.stamp + (item.args[1] || 10)) {
					updated.push(item);
				}
			}
			timeouts = updated;
			if (func) {
				id = _setTimeout.apply(null, arguments);
				timeouts.push({id: id, stamp: now, args: [].slice.call(arguments)});
			}
		};

		window.setInterval = function(func) {
			var now = Date.parse(new Date()), i, item, id, updated = [];
			for (i = 0, len = intervals.length; i < len; i++) {
				item = intervals[i];
				if (now <= item.stamp + (item.args[1] || 10)) {
					updated.push(item);
				}
			}
			intervals = updated;
			if (func) {
				id = _setInterval.apply(null, arguments);
				intervals.push({id: id, stamp: now, args: [].slice.call(arguments)});
			}
		}

		if (window.setTimeout === _setTimeout) {
			window.clearAllTimeouts = function() {
				var killId = window.setTimeout(function() {
  			  		for (var i = killId; i > 0; i--) {
  			  			window.clearTimeout(i);
					}
				}, 200);
			};

			window.clearAllIntervals = function() {
				var killId = window.setInterval(function() {
  			  		for (var i = killId; i > 0; i--) {
  			  			window.clearInterval(i);
					}
				}, 200);
			};

			window.resetTimeouts = function(ids, fallback) {
				if (typeof fallback == "function") {
					fallback(null);
				}
				else {
					document.location.reload();
				}
			};

			window.resetIntervals = window.resetTimeouts;
		}
		else {
			window.clearAllTimeouts = function() {
				window.setTimeout();
				for (var i = 0, len = timeouts.length; i < len; i++) {
					window.clearTimeout(timeouts[i].id);
				}
			};

			window.clearAllIntervals = function() {
				window.setInterval();
				for (var i = 0, len = intervals.length; i < len; i++) {
					window.clearInterval(intervals[i].id);
				}
			};

			window.resetTimeouts = function(ids, fallback) {
				for (var i = 0, len = timeouts.length; i < len; i++) {
					if (!ids || ids.indexOf(timeouts[i].id) >= 0) {
						_setTimeout.apply(null, timeouts[i].args);
					}
				}
				if (typeof fallback == 'function') {
					fallback(timeouts.length);
				}
			};

			window.resetIntervals = function(ids, fallback) {
				for (var i = 0, len = intervals.length; i < len; i++) {
					if (!ids || ids.indexOf(intervals[i].id) >= 0) {
						_setInterval.apply(null, intervals[i].args);
					}
				}
				if (typeof fallback == 'function') {
					fallback(intervals.length);
				}
			};
		}
	}
})();
