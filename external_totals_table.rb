require 'rubygems'
require 'nessus'

outfile = File.new("vulnerabilties_totals.csv","w")

Nessus::Parse.new("//Users//ianwilliams//Documents//testdata////nessus_report_.nessus") do |scan|
	scan.each_host do |host|
		high = host.high_severity_count
		medium = host.medium_severity_count
		low = host.low_severity_count
		linestart="#{host.ip},#{high},#{medium},#{low},#{high+medium+low}"
		outfile.puts linestart
	end
end