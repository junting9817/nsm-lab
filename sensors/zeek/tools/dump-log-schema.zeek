##! Prints the logged fields and types of Zeek log records in declaration order.
##! Used as the reference for ingest/clickhouse/schema/*zeek_*.sql. Re-run and compare after a Zeek upgrade.
##!
##!   docker run --rm -v "$PWD/sensors/zeek/tools/dump-log-schema.zeek:/dump.zeek:ro" zeek/zeek:8.0.10 zeek /dump.zeek

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/files/x509
@load base/frameworks/notice
@load policy/protocols/conn/community-id-logging
@load protocols/ssl/validate-certs
@load protocols/ssl/log-hostcerts-only
@load frameworks/files/hash-all-files
@load protocols/http/software

function dump(prefix: string, rtype: string)
	{
	local fields = record_fields(rtype);
	for ( name, info in fields )
		{
		if ( ! info$log )
			next;
		if ( /^record / in info$type_name )
			dump(prefix + name + ".", sub(info$type_name, /^record /, ""));
		else
			print fmt("%s%s\t%s", prefix, name, info$type_name);
		}
	}

event zeek_init()
	{
	for ( _, t in vector("Conn::Info", "DNS::Info", "HTTP::Info", "SSL::Info", "X509::Info", "Notice::Info") )
		{
		print fmt("### %s", t);
		dump("", t);
		}
	}
