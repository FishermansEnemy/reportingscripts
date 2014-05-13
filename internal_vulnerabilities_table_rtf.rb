require 'rubygems'
require 'nessus'
require 'optparse'

$header = <<header
{\\rtf1\\ansi\\ansicpg1252\\cocoartf1138\\cocoasubrtf510
{\\fonttbl\\f0\\fswiss\\fcharset0 Helvetica;\\f1\\fnil\\fcharset0 HelveticaNeue;\\f2\\fnil\\fcharset0 HelveticaNeue-Light;
\\f3\\fnil\\fcharset0 HelveticaNeue-Medium;}
{\\colortbl;\\red255\\green255\\blue255;\\red56\\green60\\blue68;\\red126\\green126\\blue126;\\red128\\green128\\blue128;
\\red129\\green129\\blue129;\\red169\\green206\\blue60;\\red53\\green54\\blue58;\\red129\\green129\\blue129;\\red255\\green0\\blue0;
\\red255\\green111\\blue0;\\red128\\green128\\blue128;}
\\margl1440\\margr1440\\margb1800\\margt1800
\\pard\\tx560\\tx1120\\tx1680\\tx2240\\tx2800\\tx3360\\tx3920\\tx4480\\tx5040\\tx5600\\tx6160\\tx6720\\pardirnatural

\\f0\\fs24 \\cf0 \\
\\
\\itap1\\trowd \\taflags1 \\trgaph108\\trleft-108 \\trcbpat1 \\trbrdrt\\brdrnil \\trbrdrl\\brdrnil \\trbrdrr\\brdrnil 
\\clvertalt \\clshdrawnil \\clwWidth1368\\clftsWidth3 \\clheight480 \\clbrdrt\\brdrs\\brdrw5\\brdrcf5 \\clbrdrl\\brdrs\\brdrw5\\brdrcf3 \\clbrdrb\\brdrs\\brdrw60\\brdrcf6 \\clbrdrr\\brdrs\\brdrw5\\brdrcf4 \\clpadt100 \\clpadl100 \\clpadb100 \\clpadr100 \\gaph\\cellx1440
\\clvertalt \\clshdrawnil \\clwWidth1800\\clftsWidth3 \\clheight480 \\clbrdrt\\brdrs\\brdrw5\\brdrcf5 \\clbrdrl\\brdrs\\brdrw5\\brdrcf4 \\clbrdrb\\brdrs\\brdrw60\\brdrcf6 \\clbrdrr\\brdrs\\brdrw5\\brdrcf4 \\clpadt100 \\clpadl100 \\clpadb100 \\clpadr100 \\gaph\\cellx2880
\\clvertalt \\clshdrawnil \\clwWidth2449\\clftsWidth3 \\clheight480 \\clbrdrt\\brdrs\\brdrw5\\brdrcf5 \\clbrdrl\\brdrs\\brdrw5\\brdrcf4 \\clbrdrb\\brdrs\\brdrw60\\brdrcf6 \\clbrdrr\\brdrs\\brdrw5\\brdrcf4 \\clpadt100 \\clpadl100 \\clpadb100 \\clpadr100 \\gaph\\cellx4320
\\clvertalt \\clshdrawnil \\clwWidth6110\\clftsWidth3 \\clheight480 \\clbrdrt\\brdrs\\brdrw5\\brdrcf5 \\clbrdrl\\brdrs\\brdrw5\\brdrcf4 \\clbrdrb\\brdrs\\brdrw60\\brdrcf6 \\clbrdrr\\brdrs\\brdrw5\\brdrcf4 \\clpadt100 \\clpadl100 \\clpadb100 \\clpadr100 \\gaph\\cellx5760
\\clvertalt \\clshdrawnil \\clwWidth1049\\clftsWidth3 \\clheight480 \\clbrdrt\\brdrs\\brdrw5\\brdrcf5 \\clbrdrl\\brdrs\\brdrw5\\brdrcf4 \\clbrdrb\\brdrs\\brdrw60\\brdrcf6 \\clbrdrr\\brdrs\\brdrw5\\brdrcf4 \\clpadt100 \\clpadl100 \\clpadb100 \\clpadr100 \\gaph\\cellx7200
\\clvertalt \\clshdrawnil \\clwWidth557\\clftsWidth3 \\clheight480 \\clbrdrt\\brdrs\\brdrw5\\brdrcf5 \\clbrdrl\\brdrs\\brdrw5\\brdrcf4 \\clbrdrb\\brdrs\\brdrw60\\brdrcf6 \\clbrdrr\\brdrs\\brdrw5\\brdrcf3 \\clpadt100 \\clpadl100 \\clpadb100 \\clpadr100 \\gaph\\cellx8640
\\pard\\intbl\\itap1\\tx560\\tx1120\\tx1680\\tx2240\\tx2800\\tx3360\\tx3920\\tx4480\\tx5040\\tx5600\\tx6160\\tx6720\\pardeftab708\\pardirnatural

\\f1\\fs20 \\cf2 \\expnd0\\expndtw0\\kerning0
\\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\strokec2 IP Address
\\f0\\fs24 \\cf0 \\kerning1\\expnd0\\expndtw0 \\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\cell 
\\pard\\intbl\\itap1\\tx560\\tx1120\\tx1680\\tx2240\\tx2800\\tx3360\\tx3920\\tx4480\\tx5040\\tx5600\\tx6160\\tx6720\\pardeftab708\\pardirnatural

\\f1\\fs20 \\cf2 \\expnd0\\expndtw0\\kerning0
\\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\strokec2 Hostname
\\f0\\fs24 \\cf0 \\kerning1\\expnd0\\expndtw0 \\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\cell 
\\pard\\intbl\\itap1\\tx560\\tx1120\\tx1680\\tx2240\\tx2800\\tx3360\\tx3920\\tx4480\\tx5040\\tx5600\\tx6160\\tx6720\\pardeftab708\\pardirnatural\\qc

\\f1\\fs20 \\cf2 \\expnd0\\expndtw0\\kerning0
\\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\strokec2 OS
\\f0\\fs24 \\cf0 \\kerning1\\expnd0\\expndtw0 \\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\cell 
\\pard\\intbl\\itap1\\tx560\\tx1120\\tx1680\\tx2240\\tx2800\\tx3360\\tx3920\\tx4480\\tx5040\\tx5600\\tx6160\\tx6720\\pardeftab708\\pardirnatural

\\f1\\fs20 \\cf2 \\expnd0\\expndtw0\\kerning0
\\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\strokec2 Identified Vulnerability
\\f0\\fs24 \\cf0 \\kerning1\\expnd0\\expndtw0 \\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\cell 
\\pard\\intbl\\itap1\\tx560\\tx1120\\tx1680\\tx2240\\tx2800\\tx3360\\tx3920\\tx4480\\tx5040\\tx5600\\tx6160\\tx6720\\pardeftab708\\pardirnatural

\\f1\\fs20 \\cf7 \\expnd0\\expndtw0\\kerning0
\\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\strokec7 Risk Rating
\\f0\\fs24 \\cf0 \\kerning1\\expnd0\\expndtw0 \\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\cell 
\\pard\\intbl\\itap1\\tx560\\tx1120\\tx1680\\tx2240\\tx2800\\tx3360\\tx3920\\tx4480\\tx5040\\tx5600\\tx6160\\tx6720\\pardeftab708\\pardirnatural

\\f1\\fs20 \\cf7 \\expnd0\\expndtw0\\kerning0
\\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\strokec7 CVSS Score
\\f0\\fs24 \\cf0 \\kerning1\\expnd0\\expndtw0 \\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\cell \\row

header

class Host

	attr_accessor :ip, :name, :os, :vulns

	def initialize(ip, name, os)

		@ip = ip
		@name = name
		@os = os
		@vulns = []
	end

	def rftout()

	output = ""
	firstline = true

	vulns.each do |vuln|
		puts vuln.severity
		case vuln.severity
		when "CRITICAL"
			colour = "cf9"
		when "HIGH"
			colour = "cf9"
		when "MEDIUM"
			colour = "cf10" 
		end
		puts colour
		if firstline
			output += <<line
\\itap1\\trowd \\taflags1 \\trgaph108\\trleft-108 \\trcbpat1 \\trbrdrl\\brdrnil \\trbrdrr\\brdrnil 
\\clvmgf \\clvertalt \\clcbpat1 \\clwWidth1368\\clftsWidth3 \\clheight4000 \\clbrdrt\\brdrs\\brdrw5\\brdrcf8 \\clbrdrl\\brdrs\\brdrw5\\brdrcf3 \\clbrdrb\\brdrs\\brdrw5\\brdrcf8 \\clbrdrr\\brdrs\\brdrw5\\brdrcf4 \\clpadt100 \\clpadl100 \\clpadb100 \\clpadr100 \\gaph\\cellx1440
\\clvmgf \\clvertalt \\clcbpat1 \\clwWidth1800\\clftsWidth3 \\clheight4000 \\clbrdrt\\brdrs\\brdrw5\\brdrcf8 \\clbrdrl\\brdrs\\brdrw5\\brdrcf4 \\clbrdrb\\brdrs\\brdrw5\\brdrcf8 \\clbrdrr\\brdrs\\brdrw5\\brdrcf4 \\clpadt100 \\clpadl100 \\clpadb100 \\clpadr100 \\gaph\\cellx2880
\\clvmgf \\clvertalt \\clcbpat1 \\clwWidth2449\\clftsWidth3 \\clheight4000 \\clbrdrt\\brdrs\\brdrw5\\brdrcf8 \\clbrdrl\\brdrs\\brdrw5\\brdrcf4 \\clbrdrb\\brdrs\\brdrw5\\brdrcf8 \\clbrdrr\\brdrs\\brdrw5\\brdrcf4 \\clpadt100 \\clpadl100 \\clpadb100 \\clpadr100 \\gaph\\cellx4320
\\clvertalt \\clcbpat1 \\clwWidth6110\\clftsWidth3 \\clheight220 \\clbrdrt\\brdrs\\brdrw5\\brdrcf8 \\clbrdrl\\brdrs\\brdrw5\\brdrcf4 \\clbrdrb\\brdrs\\brdrw5\\brdrcf8 \\clbrdrr\\brdrs\\brdrw5\\brdrcf4 \\clpadt100 \\clpadl100 \\clpadb100 \\clpadr100 \\gaph\\cellx5760
\\clvertalt \\clcbpat1 \\clwWidth1049\\clftsWidth3 \\clheight220 \\clbrdrt\\brdrs\\brdrw5\\brdrcf8 \\clbrdrl\\brdrs\\brdrw5\\brdrcf4 \\clbrdrb\\brdrs\\brdrw5\\brdrcf8 \\clbrdrr\\brdrs\\brdrw5\\brdrcf4 \\clpadt100 \\clpadl100 \\clpadb100 \\clpadr100 \\gaph\\cellx7200
\\clvertalt \\clcbpat1 \\clwWidth557\\clftsWidth3 \\clheight220 \\clbrdrt\\brdrs\\brdrw5\\brdrcf8 \\clbrdrl\\brdrs\\brdrw5\\brdrcf4 \\clbrdrb\\brdrs\\brdrw5\\brdrcf8 \\clbrdrr\\brdrs\\brdrw5\\brdrcf3 \\clpadt100 \\clpadl100 \\clpadb100 \\clpadr100 \\gaph\\cellx8640
\\pard\\intbl\\itap1\\tx560\\tx1120\\tx1680\\tx2240\\tx2800\\tx3360\\tx3920\\tx4480\\tx5040\\tx5600\\tx6160\\tx6720\\pardeftab708\\pardirnatural
\\f2\\fs18 \\cf0 \\expnd0\\expndtw0\\kerning0
\\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\strokec0 #{@ip}
\\f0\\fs24 \\cf0 \\kerning1\\expnd0\\expndtw0 \\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\cell 
\\pard\\intbl\\itap1\\tx560\\tx1120\\tx1680\\tx2240\\tx2800\\tx3360\\tx3920\\tx4480\\tx5040\\tx5600\\tx6160\\tx6720\\pardeftab708\\pardirnatural

\\f2\\fs18 \\cf0 \\expnd0\\expndtw0\\kerning0
\\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\strokec0 #{@name}
\\f0\\fs24 \\cf0 \\kerning1\\expnd0\\expndtw0 \\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\cell 
\\pard\\intbl\\itap1\\tx560\\tx1120\\tx1680\\tx2240\\tx2800\\tx3360\\tx3920\\tx4480\\tx5040\\tx5600\\tx6160\\tx6720\\pardeftab708\\pardirnatural\\qc

\\f1\\fs18 \\cf0 \\expnd0\\expndtw0\\kerning0
\\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\strokec0 #{@os}
\\f0\\fs24 \\cf0 \\kerning1\\expnd0\\expndtw0 \\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\cell 
\\pard\\intbl\\itap1\\tx560\\tx1120\\tx1680\\tx2240\\tx2800\\tx3360\\tx3920\\tx4480\\tx5040\\tx5600\\tx6160\\tx6720\\pardeftab708\\pardirnatural

\\f3\\fs18 \\#{colour} \\expnd0\\expndtw0\\kerning0
\\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\strokec9 #{vuln.name}
\\f0\\fs24 \\cf0 \\kerning1\\expnd0\\expndtw0 \\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\cell 
\\pard\\intbl\\itap1\\tx560\\tx1120\\tx1680\\tx2240\\tx2800\\tx3360\\tx3920\\tx4480\\tx5040\\tx5600\\tx6160\\tx6720\\pardeftab708\\pardirnatural

\\f3\\fs20 \\#{colour} \\expnd0\\expndtw0\\kerning0
\\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\strokec9 #{vuln.severity}
\\f0\\fs24 \\cf0 \\kerning1\\expnd0\\expndtw0 \\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\cell 
\\pard\\intbl\\itap1\\tx560\\tx1120\\tx1680\\tx2240\\tx2800\\tx3360\\tx3920\\tx4480\\tx5040\\tx5600\\tx6160\\tx6720\\pardeftab708\\pardirnatural

\\f3\\fs20 \\#{colour} \\expnd0\\expndtw0\\kerning0
\\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\strokec9 #{vuln.cvss}
\\f0\\fs24 \\cf0 \\kerning1\\expnd0\\expndtw0 \\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\cell \\row

line
		firstline = false
		else
			output += <<line
\\itap1\\trowd \\taflags1 \\trgaph108\\trleft-108 \\trcbpat1 \\trbrdrl\\brdrnil \\trbrdrr\\brdrnil 
\\clvmrg \\clvertalt \\clcbpat1 \\clwWidth1368\\clftsWidth3 \\clheight240 \\clbrdrt\\brdrs\\brdrw5\\brdrcf8 \\clbrdrl\\brdrs\\brdrw5\\brdrcf3 \\clbrdrb\\brdrs\\brdrw5\\brdrcf8 \\clbrdrr\\brdrs\\brdrw5\\brdrcf4 \\clpadt100 \\clpadl100 \\clpadb100 \\clpadr100 \\gaph\\cellx1440
\\clvmrg \\clvertalt \\clcbpat1 \\clwWidth1800\\clftsWidth3 \\clheight240 \\clbrdrt\\brdrs\\brdrw5\\brdrcf8 \\clbrdrl\\brdrs\\brdrw5\\brdrcf4 \\clbrdrb\\brdrs\\brdrw5\\brdrcf8 \\clbrdrr\\brdrs\\brdrw5\\brdrcf4 \\clpadt100 \\clpadl100 \\clpadb100 \\clpadr100 \\gaph\\cellx2880
\\clvmrg \\clvertalt \\clcbpat1 \\clwWidth2449\\clftsWidth3 \\clheight240 \\clbrdrt\\brdrs\\brdrw5\\brdrcf8 \\clbrdrl\\brdrs\\brdrw5\\brdrcf4 \\clbrdrb\\brdrs\\brdrw5\\brdrcf8 \\clbrdrr\\brdrs\\brdrw5\\brdrcf4 \\clpadt100 \\clpadl100 \\clpadb100 \\clpadr100 \\gaph\\cellx4320
\\clvertalt \\clcbpat1 \\clwWidth6110\\clftsWidth3 \\clheight240 \\clbrdrt\\brdrs\\brdrw5\\brdrcf8 \\clbrdrl\\brdrs\\brdrw5\\brdrcf4 \\clbrdrb\\brdrs\\brdrw5\\brdrcf8 \\clbrdrr\\brdrs\\brdrw5\\brdrcf4 \\clpadt100 \\clpadl100 \\clpadb100 \\clpadr100 \\gaph\\cellx5760
\\clvertalt \\clcbpat1 \\clwWidth1049\\clftsWidth3 \\clheight240 \\clbrdrt\\brdrs\\brdrw5\\brdrcf8 \\clbrdrl\\brdrs\\brdrw5\\brdrcf4 \\clbrdrb\\brdrs\\brdrw5\\brdrcf8 \\clbrdrr\\brdrs\\brdrw5\\brdrcf4 \\clpadt100 \\clpadl100 \\clpadb100 \\clpadr100 \\gaph\\cellx7200
\\clvertalt \\clcbpat1 \\clwWidth557\\clftsWidth3 \\clheight240 \\clbrdrt\\brdrs\\brdrw5\\brdrcf8 \\clbrdrl\\brdrs\\brdrw5\\brdrcf4 \\clbrdrb\\brdrs\\brdrw5\\brdrcf8 \\clbrdrr\\brdrs\\brdrw5\\brdrcf3 \\clpadt100 \\clpadl100 \\clpadb100 \\clpadr100 \\gaph\\cellx8640
\\pard\\intbl\\itap1\\cell
\\pard\\intbl\\itap1\\cell
\\pard\\intbl\\itap1\\cell
\\pard\\intbl\\itap1\\tx560\\tx1120\\tx1680\\tx2240\\tx2800\\tx3360\\tx3920\\tx4480\\tx5040\\tx5600\\tx6160\\tx6720\\pardeftab708\\pardirnatural
\\f3\\fs18 \\#{colour} \\expnd0\\expndtw0\\kerning0
\\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\strokec9 #{vuln.name}
\\f0\\fs24 \\cf0 \\kerning1\\expnd0\\expndtw0 \\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\cell 
\\pard\\intbl\\itap1\\tx560\\tx1120\\tx1680\\tx2240\\tx2800\\tx3360\\tx3920\\tx4480\\tx5040\\tx5600\\tx6160\\tx6720\\pardeftab708\\pardirnatural

\\f3\\fs20 \\#{colour} \\expnd0\\expndtw0\\kerning0
\\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\strokec9 #{vuln.severity}
\\f0\\fs24 \\cf0 \\kerning1\\expnd0\\expndtw0 \\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\cell 
\\pard\\intbl\\itap1\\tx560\\tx1120\\tx1680\\tx2240\\tx2800\\tx3360\\tx3920\\tx4480\\tx5040\\tx5600\\tx6160\\tx6720\\pardeftab708\\pardirnatural

\\f3\\fs20 \\#{colour} \\expnd0\\expndtw0\\kerning0
\\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\strokec9 #{vuln.cvss}
\\f0\\fs24 \\cf0 \\kerning1\\expnd0\\expndtw0 \\up0 \\nosupersub \\ulnone \\outl0\\strokewidth0 \\cell \\row

line
		end
	end
	return output
	end

end

class Vuln

	attr_accessor :name, :severity, :cvss

	def initialize(name, severity, cvss)

	@name = name 
	@severity = severity
	@cvss = cvss

end

options = {}

optparse = OptionParser.new do|opt|
	opt.banner = "Usage: internal_vunerabilities_table_rtf --nessus [NESSUSFILE]"
	  opt.separator  ""
	  opt.separator  "Options"

	opt.on( '-n', '--nessus NESSUSFILE', "Nessus XML file" ) do|nessus|
  		options[:nessus] = nessus
	end
end

optparse.parse!

#outfile = File.new("vulnerabilties.csv","w")
outfilenumber = 1
outfile = File.new("vulnerabilties-#{outfilenumber}.rtf","w")

hosts = []

Nessus::Parse.new(options[:nessus]) do |scan|
	scan.each_host do |host|
		operatingsystem = ""
		operatingsystem = host.os.delete"\n" if host.os.respond_to?('delete')
		hosts.push(Host.new(host.ip,host.netbios_name,operatingsystem))
		puts host.ip
		hostindex = hosts.find_index { |item| item.ip == host.ip }
		host.each_event do |event|
			if (event.severity.medium? || event.severity.high? || event.severity.critical?)
				hosts[hostindex].vulns.push(Vuln.new(event.name,event.severity.in_words.upcase.split(' ')[0],event.cvss_base_score))
			end
		end
		hosts[hostindex].vulns.sort!{ |a,b| (b.cvss == a.cvss) ? a.name <=> b.name : b.cvss <=> a.cvss}
		hosts.delete_at(hostindex) if hosts[hostindex].vulns.empty?
	end

	outfile.puts $header
	hosts.each do |host|
		puts host.ip
		outfile.puts host.rftout
		if outfile.size > 500000
			outfile.puts("}")
			outfile.close
			outfilenumber+=1
			outfile = File.new("vulnerabilties-#{outfilenumber}.rtf","w")
			outfile.puts $header
		end
	end
	outfile.puts("}")
	outfile.close
end
end