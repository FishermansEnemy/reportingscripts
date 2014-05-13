require 'rubygems'
require 'nessus'
require 'nmap/parser'
require 'optparse'

options = {}

optparse = OptionParser.new do|opt|
	opt.banner = "Usage: external_ports_table --nessus [NESSUSFILE] --nmap [NMAPFILE]"
	  opt.separator  ""
	  opt.separator  "Options"

	opt.on( '-n', '--nessus NESSUSFILE', "Nessus XML file" ) do|nessus|
  		options[:nessus] = nessus
	end
	opt.on( '-m', '--nmap NMAPFILE', "nmap XML file" ) do|nmap|
  		options[:nmap] = nmap
	end
end

optparse.parse!

outfile = File.new("openports.csv","w")

Nessus::Parse.new(options[:nessus]) do |scan|
	scan.each_host do |host|
		os = "#{host.os}"
		os.delete!("\n")
		linestart="#{host.ip},#{os}"
		Nmap::Parser.parsefile(options[:nmap]) do |nmap|
			nmaphost = nmap.host(host.ip)
			[:tcp, :udp].each do |type|
                nmaphost.getports(type, "open") do |port|
                	srv = port.service
                	outfile.puts linestart+",#{port.proto.to_s.upcase}/#{port.num},#{srv.product} #{srv.version}" if srv.version
                	outfile.puts linestart+",#{port.proto.to_s.upcase}/#{port.num},#{srv.name}" if !srv.version
                	linestart=","
				end
			end
		end
	end
end