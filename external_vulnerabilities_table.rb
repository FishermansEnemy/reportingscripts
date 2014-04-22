require 'rubygems'
require 'nessus'

outfile = File.new("vulnerabilties.csv","w")

Nessus::Parse.new("//Users//ianwilliams//Documents//testdata////nessus_report_.nessus") do |scan|
	scan.each_host do |host|
		high = host.high_severity_count
		medium = host.medium_severity_count
		low = host.low_severity_count
		linestart="#{host.ip},#{host.os}"
		host.each_event do |event|
			lineend=",#{event.port.protocol}/#{event.port.number},"
			if event.name.include? "Version" then
				lineend+= "#{event.data}"
				puts linestart+lineend
				linestart=","
			end
		end
	end
end