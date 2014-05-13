require 'rubygems'
require 'nessus'

outfile = File.new("vulnerabilties.csv","w")

Nessus::Parse.new("//Users//ianwilliams//Documents//testdata//nessus_report.nessus") do |scan|
	scan.each_host do |host|
		high = host.high_severity_count
		medium = host.medium_severity_count
		low = host.low_severity_count
		linestart="#{host.ip},#{host.netbios_name},"
		linestart+="#{host.os.delete"\n"}" if host.os.respond_to?('delete')
		host.each_event do |event|
			lineend=",#{event.name.delete','},#{event.severity.in_words.upcase.split(' ')[0]},#{event.cvss_base_score}"
			if (event.severity.medium? || event.severity.high? || event.severity.critical?)
				outfile.puts linestart+lineend
				linestart = ",,"
			end
		end
	end
end