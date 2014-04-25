require 'rubygems'
require 'nessus'

class Vuln

	attr_accessor :cve, :bid, :sources, :xrefs, :hosts, :pid, :cvss, :name

	def initialize(pid, name, cvss)
		# instance variables
		@pid = pid
		@name = name
		@cvss = cvss
		@cve = []
		@bid = [] 
		@sources = [] 
		@xrefs = [] 
		@hosts = []
	end

	def to_s()
		return "#{@pid}:#{@name}:#{@cvss}:#{cve}:#{xrefs}:#{hosts}"
	end

	def to_html()
		htmlout = "#{@name} (CVSS:#{@cvss})<br>"
		htmlout += "CVE: "
		@cve.each do |cve|
			htmlout += "<a href=\"http://web.nvd.nist.gov/view/vuln/detail?vulnId=#{cve}\">#{cve}</a>, "
		end
		htmlout += "<br>BID: "
		@bid.each do |bid|
			htmlout += "<a href=\"http://www.securityfocus.com/bid/#{bid}\">#{bid}</a>, "
		end
		@sources.each do |source|
			htmlout += "<br>#{source}: "
			@xrefs.each do |xref|
				if xref.include? source
					if ["OSVDB", "CWE", "Secunia", "CERT", "EDB-ID", "VMSA"].include? source
						htmlout += "<a href=\"http://osvdb.org/#{xref.split(':')[1]}\">#{xref.split(':')[1]}</a>, " if source == "OSVDB"
						htmlout += "<a href=\"http://cwe.mitre.org/data/definitions/#{xref.split(':')[1]}\">#{xref.split(':')[1]}</a>, " if source == "CWE"
						htmlout += "<a href=\"http://secunia.com/advisories/#{xref.split(':')[1]}\">#{xref.split(':')[1]}</a>, " if source == "Secunia"
						htmlout += "<a href=\"http://www.kb.cert.org/vuls/id/#{xref.split(':')[1]}\">#{xref.split(':')[1]}</a>, " if source == "CERT"
						htmlout += "<a href=\"http://www.exploit-db.com/exploits/#{xref.split(':')[1]}\">#{xref.split(':')[1]}</a>, " if source == "EDB-ID"
						htmlout += "<a href=\"https://www.vmware.com/security/advisories/VMSA-#{xref.split(':')[1]}.html\">#{xref.split(':')[1]}</a>, " if source == "VMSA"
					else htmlout += "#{xref.split(':')[1]}, "
					end
				end
			end
		end
		htmlout += "<br>"
		htmlout += "<pre style=\"word-wrap: break-word; white-space; pre-wrap\">"
		linecount = 0
		@hosts.each do |host|
			htmlout += "#{host}\t"
			linecount +=1
			if linecount == 4
				htmlout += "\n"
				linecount =0
			end
		end
		htmlout +=("</pre><hr>")
		return htmlout
	end
end

vulns = Array.new()

Nessus::Parse.new("//Users//ianwilliams//Documents//testdata//nessus_report.nessus") do |scan|
	scan.each_host do |host|
		host.each_event do |event|
			if (event.severity.medium? || event.severity.high? || event.severity.critical?)
				vulns.push(Vuln.new(event.plugin_id,event.name,(event.cvss_base_score.nil? ? 0 : event.cvss_base_score))) if !vulns.detect{|vuln| vuln.pid == event.plugin_id}
				vuln = vulns.find {|s| s.pid == event.plugin_id}
				event.cve.each do |cve|
					vuln.cve.push(cve) if !vuln.cve.include? cve
				end
				event.bid.each do |bid|
					vuln.bid.push(bid) if !vuln.bid.include? bid
				end
				event.xref.each do |xref|
					ref = xref.split(':')
					vuln.sources.push(ref[0]) if !vuln.sources.include? ref[0]
					vuln.xrefs.push(xref) if !vuln.xrefs.include? xref
				end
				vuln.hosts.push("#{host.ip}\t#{event.port.protocol.to_s.upcase}/#{event.port.number}") if !vuln.hosts.include? "#{host.ip}\t#{event.port.protocol.to_s.upcase}/#{event.port.number}"
			end
		end
	end
end

#vulns.sort!{ |a,b| b.cvss <=> a.cvss}
vulns.sort!{ |a,b| (b.cvss == a.cvss) ? a.name <=> b.name : b.cvss <=> a.cvss}

outfile = File.new("internal_vulnerabilities_details_fast.html","w")
outfile.puts("<HTML><BODY>")
vulns.each do |vuln|
	outfile.puts vuln.to_html()
end
outfile.puts("</BODY></HTML>")
outfile.close
