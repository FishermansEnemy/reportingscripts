require 'rubygems'
require 'nessus'
require 'optparse'

options = {}

optparse = OptionParser.new do|opt|
	opt.banner = "Usage: internal_vulnerabilities_details.rb --nessus [NESSUSFILE]"
	  opt.separator  ""
	  opt.separator  "Options"

	opt.on( '-n', '--nessus NESSUSFILE', "Nessus XML file" ) do|nessus|
  		options[:nessus] = nessus
	end
end

optparse.parse!

# Outputs a file containing the event name, references and formated hosts table for each medium, high and critical vuln

outfile = File.new("internal_vulnerabilities_details.html","w")
events = []
cves = []
bids = []
sources = []
xrefs = []
hosts = []
pids = Hash.new()

Nessus::Parse.new(options[:nessus]) do |scan|
	scan.each_host do |host|
		host.each_event do |event|
			if (event.severity.medium? || event.severity.high? || event.severity.critical?)
				pids.merge!(event.plugin_id => event.cvss_base_score) if !pids.key?(event.plugin_id)
			end
		end
	end
end

outfile.puts "<HTML>"
outfile.puts "<BODY>"

pids = Hash[(pids.sort_by{|name,cvss|cvss}.reverse)]

pids.keys.each do |pid| 
	events = []
	cves = []
	bids = []
	sources = []
	xrefs = []
	hosts = []
	Nessus::Parse.new("//Users//ianwilliams//Documents//testdata//nessus_report_.nessus") do |scan|
		scan.each_host do |host|
			host.each_event do |event|
				if event.plugin_id == pid 
					events.push event.name if !events.include? event.name
					event.cve.each do |cve|
						if !cves.include? cve
							cves.push(cve)
						end
					end
					event.bid.each do |bid|
						if !bids.include? bid
							bids.push(bid)
						end
					end
					event.xref.each do |xref|
						ref = xref.split(':')
						if !sources.include? ref[0]
							sources.push ref[0]
						end
						if !xrefs.include? xref
							xrefs.push(xref)
						end
					end
					if !hosts.include? "#{host.ip}\t#{event.port.protocol.to_s.upcase}/#{event.port.number}"
						hosts.push "#{host.ip}\t#{event.port.protocol.to_s.upcase}/#{event.port.number}"
					end
				end
			end
		end

		xrefs = xrefs.sort.reverse
		cves = cves.sort.reverse
		bids = bids.sort.reverse

		events.each do |event|
			puts event
			outfile.puts "#{event}<br>"
		end
		outfile.puts "<br>CVE: "
		cves.each do |cve|
			outfile.puts "<a href=\"http://web.nvd.nist.gov/view/vuln/detail?vulnId=#{cve}\">#{cve}</a>, "
		end
		outfile.puts "<br>BID: "
		bids.each do |bid|
			outfile.puts "<a href=\"http://www.securityfocus.com/bid/#{bid}\">#{bid}</a>, "
		end
		sources.each do |source|
			outfile.puts "<br>#{source}: "
			xrefs.each do |xref|
				if xref.include? source
					if ["OSVDB", "CWE", "Secunia", "CERT", "EDB-ID", "VMSA"].include? source
						outfile.puts "<a href=\"http://osvdb.org/#{xref.split(':')[1]}\">#{xref.split(':')[1]}</a>, " if source == "OSVDB"
						outfile.puts "<a href=\"http://cwe.mitre.org/data/definitions/#{xref.split(':')[1]}\">#{xref.split(':')[1]}</a>, " if source == "CWE"
						outfile.puts "<a href=\"http://secunia.com/advisories/#{xref.split(':')[1]}\">#{xref.split(':')[1]}</a>, " if source == "Secunia"
						outfile.puts "<a href=\"http://www.kb.cert.org/vuls/id/#{xref.split(':')[1]}\">#{xref.split(':')[1]}</a>, " if source == "CERT"
						outfile.puts "<a href=\"http://www.exploit-db.com/exploits/#{xref.split(':')[1]}\">#{xref.split(':')[1]}</a>, " if source == "EDB-ID"
						outfile.puts "<a href=\"https://www.vmware.com/security/advisories/VMSA-#{xref.split(':')[1]}.html\">#{xref.split(':')[1]}</a>, " if source == "VMSA"
					else outfile.puts "#{xref.split(':')[1]}, "
					end
				end
			end
		end
		outfile.puts "<br>"
		outfile.puts "<pre style=\"word-wrap: break-word; white-space; pre-wrap\">"
		linecount = 0
		hosts.each do |host|
			outfile.print "#{host}\t"
			linecount +=1
			if linecount == 4
				outfile.puts "\n"
				linecount =0
			end
		end
		outfile.puts("</pre><hr>")
	end
end
outfile.puts("</body></html>")
outfile.close