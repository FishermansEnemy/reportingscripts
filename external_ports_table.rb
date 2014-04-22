require 'rubygems'
require 'nessus'
require 'nmap/parser'

outfile = File.new("openports.csv","w")

Nessus::Parse.new("//Users//ianwilliams//Documents//testdata//nessus_report_.nessus") do |scan|
	scan.each_host do |host|
		os = "#{host.os}"
		os.delete!("\n")
		linestart="#{host.ip},#{os}"
		Nmap::Parser.parsefile("//Users//ianwilliams//Documents//testdata//nmap.xml") do |nmap|
			nmaphost = nmap.host(host.ip)
			[:tcp, :udp].each do |type|
                nmaphost.getports(type, "open") do |port|
                	srv = port.service
                	outfile.puts linestart+",#{port.proto}/#{port.num},#{srv.product} #{srv.version}" if srv.version
                	outfile.puts linestart+",#{port.proto}/#{port.num},#{srv.name}" if !srv.version
                	linestart=","
				end
			end
		end
	end
end