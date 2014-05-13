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

outfile = File.new("vulnerabilties_totals.csv","w")

Nessus::Parse.new(options[:nessus]) do |scan|
	scan.each_host do |host|
		high = host.high_severity_count + host.critical_severity_count
		medium = host.medium_severity_count
		low = host.low_severity_count
		linestart="#{host.ip},#{high},#{medium},#{low},#{high+medium+low}"
		outfile.puts linestart
	end
end