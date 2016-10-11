// JavaScript Utilities
// Copyright (C) 2014-2016 Bernhard Waldbrunner
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

	if (!Function.method)
	{
		Function.prototype.method = function (name, func) {
			if (!this.prototype[name])
				this.prototype[name] = func;
			return this;
		};

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
	}

	if (!Object.create)
	{
		Object.create = function (o) {
			var F = function () {};
			F.prototype = o;
			return new F();
		};
	}

	if (!Object.prototype.extend)
	{
		Object.prototype.extend = function(props) {
			var key, val, obj = {};
			for (key in props) {
				val = props[key];
				obj[key] = val;
			}
			return obj;
		};
	}

	if (!Array.isArray)
	{
		Array.isArray = function(obj) {
			return obj && typeof obj == 'object' && typeof obj.length == 'number' &&
				!obj.propertyIsEnumerable('length');
		};
	}

	if (!Number.isNumber)
	{
		Number.isNumber = function(val) {
			return typeof val == 'number' && isFinite(val);
		};
	}

	if (!Array.dim)
	{
		Array.copy = function(a) {
			var ary = [], i;
			for (i = a.length >>> 0; i--;)
			{
				if (Array.isArray(a[i]))
					ary[i] = Array.copy(a[i]);
				else if (typeof a[i] == 'object')
					ary[i] = Object.create(a[i]);
				else
					ary[i] = a[i];
			}
			return ary;
		};

		Array.dim = function(length, initial) {
			var a = [], i, ary = Array.isArray(initial), obj = (typeof initial == 'object');
			for (i = 0; i < length; i++)
				a[i] = (ary ? initial.copy() : (obj ? Object.create(initial) : initial));
			return a;
		};

		Array.method('reduce', function(f, val) {
			var i;
			for (i = 0; i < this.length; i++)
				val = f(this[i], val);
			return val;
		});

		RegExp.quote = function (str) {
			return str.replace(/[.?*+^$[\]\\(){}|-]/g, "\\$&");
		};

		Object.getKey = function (obj, val, type, idx) {
			if (typeof obj != "object" || obj == null)
				return null;
			idx = (typeof idx == "undefined" ? 0 : parseInt(idx));
			var i = 0, k;
			for (k in obj)
			{
				if ((!type || typeof obj[k] == type) && idx == i++ && val === obj[k])
					return k;
			}
			return false;
		};
	}

	var MAIL_RX;

	if (!String.prototype.linkify) {
		String.prototype.linkify = (function () {
		  var
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
		    var URI_RE = new RegExp( "(?:" + URI1 + "|" + URI2 + "|" + EMAIL + ")", "ig" ),
		    SCHEME_RE = new RegExp( "^" + SCHEME, "i" ),

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
		      callback: function( text, href ) {
		        return href ? '<a href="' + href + '" title="' + href + '">' + text + '</a>' : text;
		      },
		      punct_regexp: /(?:[!?.,:;'"]|(?:&|&amp;)(?:lt|gt|quot|apos|raquo|laquo|rsaquo|lsaquo);)$/
		    };

		  return function( options ) {
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
		    for ( i in default_options ) {
		      if ( options[ i ] === undefined ) {
		        options[ i ] = default_options[ i ];
		      }
		    }

		    // Find links.
		    while ( arr = URI_RE.exec( txt ) ) {

		      link = arr[0];
		      idx_last = URI_RE.lastIndex;
		      idx = idx_last - link.length;

		      // Not a link if preceded by certain characters.
		      if ( /[\/:]/.test( txt.charAt( idx - 1 ) ) ) {
		        continue;
		      }

		      // Trim trailing punctuation.
		      do {
		        // If no changes are made, we don't want to loop forever!
		        link_last = link;

		        quote_end = link.substr( -1 );
		        quote_begin = quotes[ quote_end ];

		        // Ending quote character?
		        if ( quote_begin ) {
		          matches_begin = link.match( new RegExp( '\\' + quote_begin + '(?!$)', 'g' ) );
		          matches_end = link.match( new RegExp( '\\' + quote_end, 'g' ) );

		          // If quotes are unbalanced, remove trailing quote character.
		          if ( ( matches_begin ? matches_begin.length : 0 ) < ( matches_end ? matches_end.length : 0 ) ) {
		            link = link.substr( 0, link.length - 1 );
		            idx_last--;
		          }
		        }

		        // Ending non-quote punctuation character?
		        if ( options.punct_regexp ) {
		          link = link.replace( options.punct_regexp, replacePunctuation);
		        }
		      } while ( link.length && link !== link_last );

		      href = link;

		      // Add appropriate protocol to naked links.
		      if ( !SCHEME_RE.test( href ) ) {
		        href = ( href.indexOf( '@' ) !== -1 ? ( !href.indexOf( MAILTO ) ? '' : MAILTO )
		          : !href.indexOf( 'irc.' ) ? 'irc://'
		          : !href.indexOf( 'ftp.' ) ? 'ftp://'
		          : 'http://' )
		          + href;
		      }

		      // Push preceding non-link text onto the array.
		      if ( idx_prev != idx ) {
		        parts.push([ txt.slice( idx_prev, idx ) ]);
		        idx_prev = idx_last;
		      }

		      // Push massaged link onto the array
		      parts.push([ link, href ]);
		    }

		    // Push remaining non-link text onto the array.
		    parts.push([ txt.substr( idx_prev ) ]);

		    // Process the array items.
		    for ( i = 0; i < parts.length; i++ ) {
		      html += options.callback.apply( window, parts[i] );
		    }

		    // In case of catastrophic failure, return the original text;
		    return html || txt;
		  };

		})();
	}

	if (!String.prototype.isEmail) {
		String.prototype.isEmail = function () {
			return MAIL_RX.test(this);
		};
	}
	if (!String.prototype.toURIComponent) {
		String.prototype.toURIComponent = function (separator) {
			if (typeof separator == 'undefined')
				separator = '-';

			var s = this.toLowerCase(), str = '', space = true, start = true;
			for (var i = 0; i < s.length; i++)
			{
				var c = s.charCodeAt(i);
				if ((c >= 97 && c <= 122) || (c >= 48 && c <= 57)) // [a-z0-9]
				{
					if (space && !start)
						str += separator;
					str += s.charAt(i);
					space = false;
					start = false;
				}
				else if (c == 95 || c == 32 || c == 45 || c == 9 || c == 10) // [\s_-]
					space = true;
			}
			return str;
		};
	}

	if (!String.prototype.escape) {
		String.method('escape', function () {
			return this.replace(/\\/g, '\\\\')
					   .replace(/'/g, "\\'")
					   .replace(/"/g, '\\"');
		});

		String.method('unescape', function () {
			return this.replace(/\\\\/g, '\001/')
					   .replace(/\\t/g, "\t")
					   .replace(/\\b/g, "\b")
					   .replace(/\\f/g, "\f")
					   .replace(/\\n/g, "\n")
					   .replace(/\\r/g, "\r")
					   .replace(/\\v/g, "\v")
					   .replace(/\\'/g, "'")
					   .replace(/\\"/g, '"')
					   .replace(/\001\//g, "\\");
		});
	}
})();