##! Adds the TLS client fingerprints JA3 and JA4 to ssl.log (ja3, ja4 fields).
##!
##! Zeek 8.0.10 does not ship them, so they are implemented from the public specifications.
##!   - JA3 : https://github.com/salesforce/ja3 (BSD-3-Clause)
##!           md5("ClientHello version,ciphers,extensions,elliptic curves,point formats"), decimal values joined with '-', GREASE removed
##!   - JA4 : the JA4 (TLS client) specification at https://github.com/FoxIO-LLC/ja4 (BSD-3-Clause)
##!           <t><version><SNI d|i><cipher count><extension count><ALPN first+last char>_<sha256[:12] of sorted ciphers>_<sha256[:12] of sorted extensions+signature algorithms>
##! Correctness is checked against Suricata 8's built-in JA3/JA4 on the same PCAPs (testing/fingerprints/crosscheck.sh).
##!
##! Event order (observed on Zeek 8.0.10): a ClientHello's extension events arrive before ssl_client_hello.
##! If a HelloRetryRequest causes a second ClientHello, only the first one is used.

module NSMFingerprint;

export {
	## If T, also log the pre-hash raw string (FoxIO's JA4_r) as ja4_r. Off in production; on only for cross-checks.
	const log_ja4_raw = F &redef;

	redef record SSL::Info += {
		## JA3 TLS client fingerprint (md5 hex)
		ja3: string &log &optional;
		## JA4 TLS client fingerprint
		ja4: string &log &optional;
		## Raw JA4: <JA4_a>_<sorted ciphers>_<sorted extensions (without SNI and ALPN)>[_<signature algorithms>]
		ja4_r: string &log &optional;
	};
}

type ClientHelloState: record {
	done: bool &default=F;
	version: count &default=0;
	ciphers: index_vec &optional;
	extensions: index_vec &optional;
	curves: index_vec &optional;
	point_formats: index_vec &optional;
	sig_algs: index_vec &optional;
	supported_versions: index_vec &optional;
	alpn: string &default="";
};

redef record connection += {
	nsm_hello: ClientHelloState &optional;
};

function state(c: connection): ClientHelloState
	{
	if ( ! c?$nsm_hello )
		c$nsm_hello = ClientHelloState($ciphers=vector(), $extensions=vector(), $curves=vector(),
		                               $point_formats=vector(), $sig_algs=vector(), $supported_versions=vector());
	return c$nsm_hello;
	}

# GREASE (RFC 8701): 0x0a0a, 0x1a1a, ... 0xfafa — both bytes equal and the low nibble is 0xa
function is_grease(v: count): bool
	{
	return v / 256 == v % 256 && v % 16 == 10;
	}

function without_grease(v: index_vec): index_vec
	{
	local out: index_vec = vector();
	for ( _, x in v )
		if ( ! is_grease(x) )
			out += x;
	return out;
	}

function join_dec(v: index_vec): string
	{
	local parts: string_vec = vector();
	for ( _, x in v )
		parts += cat(x);
	return join_string_vec(parts, "-");
	}

function join_hex4(v: index_vec): string
	{
	local parts: string_vec = vector();
	for ( _, x in v )
		parts += fmt("%04x", x);
	return join_string_vec(parts, ",");
	}

function sorted_copy(v: index_vec): index_vec
	{
	local out: index_vec = copy(v);
	sort(out);
	return out;
	}

function ja4_version(s: ClientHelloState): string
	{
	local v = s$version;
	local sv = without_grease(s$supported_versions);
	if ( |sv| > 0 )
		{
		v = 0;
		for ( _, x in sv )
			if ( x > v )
				v = x;
		}
	switch ( v ) {
		case 0x0304: return "13";
		case 0x0303: return "12";
		case 0x0302: return "11";
		case 0x0301: return "10";
		case 0x0300: return "s3";
		case 0x0002: return "s2";
		case 0xfeff: return "d1";
		case 0xfefd: return "d2";
		case 0xfefc: return "d3";
		default: return "00";
	}
	}

function is_alnum(ch: string): bool
	{
	return /^[0-9A-Za-z]$/ in ch;
	}

function ja4_alpn(alpn: string): string
	{
	if ( |alpn| == 0 )
		return "00";
	local first = alpn[0];
	local last = alpn[|alpn| - 1];
	if ( is_alnum(first) && is_alnum(last) )
		return first + last;
	# If not alphanumeric: first char of the first byte's hex + last char of the last byte's hex
	local fh = bytestring_to_hexstr(first);
	local lh = bytestring_to_hexstr(last);
	return fh[0] + lh[1];
	}

function trunc_sha256(s: string): string
	{
	return sub_bytes(sha256_hash(s), 1, 12);
	}

function compute_ja3(s: ClientHelloState): string
	{
	local raw = fmt("%d,%s,%s,%s,%s", s$version,
	                join_dec(without_grease(s$ciphers)), join_dec(without_grease(s$extensions)),
	                join_dec(without_grease(s$curves)), join_dec(without_grease(s$point_formats)));
	return md5_hash(raw);
	}

## Builds JA4 and JA4_r (raw) together: [ja4, ja4_r]
function compute_ja4(s: ClientHelloState): string_vec
	{
	local ciphers = without_grease(s$ciphers);
	local exts = without_grease(s$extensions);

	local has_sni = F;
	local exts_for_hash: index_vec = vector();
	for ( _, e in exts )
		{
		if ( e == 0 )
			has_sni = T;
		# The JA4_c hash leaves out SNI (0x0000) and ALPN (0x0010) (they still count)
		if ( e != 0 && e != 16 )
			exts_for_hash += e;
		}

	local a = fmt("t%s%s%02d%02d%s", ja4_version(s), has_sni ? "d" : "i",
	              |ciphers| > 99 ? 99 : |ciphers|, |exts| > 99 ? 99 : |exts|, ja4_alpn(s$alpn));

	local b_raw = join_hex4(sorted_copy(ciphers));
	local b = |ciphers| == 0 ? "000000000000" : trunc_sha256(b_raw);

	# Spec: without signature algorithms, hash the string with no trailing underscore
	#       (Suricata 8.0.6 appends "_" here before hashing, so its value differs — docs/architecture.md section 11)
	local c_raw = join_hex4(sorted_copy(exts_for_hash));
	local sigs = without_grease(s$sig_algs);
	if ( |sigs| > 0 )
		c_raw = c_raw + "_" + join_hex4(sigs);
	local c_str = |exts_for_hash| == 0 ? "000000000000" : trunc_sha256(c_raw);

	return vector(fmt("%s_%s_%s", a, b, c_str), fmt("%s_%s_%s", a, b_raw, c_raw));
	}

event ssl_extension(c: connection, is_client: bool, code: count, val: string) &priority=6
	{
	if ( ! is_client )
		return;
	local s = state(c);
	if ( ! s$done )
		s$extensions += code;
	}

event ssl_extension_elliptic_curves(c: connection, is_client: bool, curves: index_vec) &priority=6
	{
	if ( ! is_client )
		return;
	local s = state(c);
	if ( ! s$done )
		s$curves = curves;
	}

event ssl_extension_ec_point_formats(c: connection, is_client: bool, point_formats: index_vec) &priority=6
	{
	if ( ! is_client )
		return;
	local s = state(c);
	if ( ! s$done )
		s$point_formats = point_formats;
	}

event ssl_extension_signature_algorithm(c: connection, is_client: bool, signature_algorithms: signature_and_hashalgorithm_vec) &priority=6
	{
	if ( ! is_client )
		return;
	local s = state(c);
	if ( s$done )
		return;
	local codes: index_vec = vector();
	for ( _, alg in signature_algorithms )
		codes += alg$HashAlgorithm * 256 + alg$SignatureAlgorithm;
	s$sig_algs = codes;
	}

event ssl_extension_supported_versions(c: connection, is_client: bool, versions: index_vec) &priority=6
	{
	if ( ! is_client )
		return;
	local s = state(c);
	if ( ! s$done )
		s$supported_versions = versions;
	}

event ssl_extension_application_layer_protocol_negotiation(c: connection, is_client: bool, protocols: string_vec) &priority=6
	{
	if ( ! is_client )
		return;
	local s = state(c);
	if ( ! s$done && |protocols| > 0 )
		s$alpn = protocols[0];
	}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) &priority=6
	{
	local s = state(c);
	if ( s$done )
		return;
	s$version = version;
	s$ciphers = ciphers;
	s$done = T;
	}

hook SSL::ssl_finishing(c: connection)
	{
	if ( ! c?$nsm_hello || ! c$nsm_hello$done || ! c?$ssl )
		return;
	c$ssl$ja3 = compute_ja3(c$nsm_hello);
	local ja4 = compute_ja4(c$nsm_hello);
	c$ssl$ja4 = ja4[0];
	if ( log_ja4_raw )
		c$ssl$ja4_r = ja4[1];
	}
