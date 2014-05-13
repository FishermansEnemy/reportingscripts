require 'rubygems'
require 'nessus'
require 'optparse'

options = {}

optparse = OptionParser.new do|opt|
	opt.banner = "Usage: external_totals_table --nessus [NESSUSFILE]"
	  opt.separator  ""
	  opt.separator  "Options"

	opt.on( '-n', '--nessus NESSUSFILE', "Nessus XML file" ) do|nessus|
  		options[:nessus] = nessus
	end
end

optparse.parse!

outfile = File.new("external_vulns.csv","w")
events = Hash.new()

Nessus::Parse.new(options[:nessus]) do |scan|
	scan.each_host do |host|
		linestart="#{host.ip},#{host.netbios_name},"
		host.each_event do |event|
			lineend="#{event.name},#{event.port.protocol.to_s.upcase}/#{event.port.number}"
			events.merge!("#{event.name},#{event.port.protocol.to_s.upcase}/#{event.port.number}"=>((event.cvss_base_score == false) ? 0 : event.cvss_base_score)) if (event.severity.low? || event.severity.medium? || event.severity.high? || event.severity.critical?)
		end
		sorted = Hash[(events.sort_by{|name,cvss|cvss}.reverse)]
		sorted.keys.each do |name|
			outfile.puts linestart+name
			linestart=",,"
		end
		events=Hash.new()
	end
end