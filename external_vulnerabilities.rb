require 'rubygems'
require 'nessus'

outfile = File.new("external_vulns.csv","w")
events = Hash.new()

Nessus::Parse.new("//Users//ianwilliams//Documents//testdata//nessus_report_.nessus") do |scan|
	scan.each_host do |host|
		linestart="#{host.ip},#{host.netbios_name},"
		host.each_event do |event|
			lineend="#{event.name},#{event.port.protocol}/#{event.port.number}"
			events.merge!("#{event.name},#{event.port.protocol}/#{event.port.number}"=>event.cvss_base_score) if event.cvss_base_score!= false
		end
		sorted = Hash[(events.sort_by{|name,cvss|cvss}.reverse)]
		sorted.keys.each do |name|
			outfile.puts linestart+name
			linestart=",,"
		end
		events=Hash.new()
	end
end