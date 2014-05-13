Helpful reporting scripts

AUTHOR: Ian Williams (Ian@fishermansenemy.com) (ian.williams@randomstorm.com)

A collection of scripts to parse nessus and nmap files into a format suitable for including into a report

REQUIRES:

Ruby 1.9.3
rubygems

Install the nmap parser gem using:
gem install nmap-parser

Note that the currently published gem for "ruby-nessus" is *not* the current version that supports multiple CVEs per host. Because of this you will need to pull down the latest version from github and install it manually:

git clone https://github.com/mephux/ruby-nessus.git
cd ruby-nessus/
gem build ruby-nessus.gemspec
gem install ruby-nessus-1.2.0.gem

USAGE:

Invoke each script as below:

ruby ./scriptname.rb --nessus /path/to/nessus/file (--nmap /path/to/nmap/file)

Each script takes either a nessus file via the --nessus [filename] paramter, or in the case of external_ports_table, a --nessus and --nmap [filename] paramter and outputs a file that you can paste directly into pages.

external_ports_table : creates a csv table containing all of the open ports for an external assessment

external_totals_table : creates a csv table containing the total vulnerabilities for each host, for an external assessment

external_vulnerabilities_table : creates a csv containing all of the vulnerabilities per host, for an external assessment

internal_vulnerabilities_table_rtf : creates several rtf files containing all Medium, High or Critical vulnerabilities, with merged cells and correct colours for an internal assessment. Due to using rtf it has to create several files as once an rtf grows above .5MB it becomes hard to parse with the builtin macOS text editor. Just paste each table in one after the other. This also helps with the pages table size truncation bug.

internal_vulnerabilities_details : creates an HTML formated file containing all of the vulnerabilities, with hotlinked references and a tab seperated table of hosts. This is useful for either creating a new vulnerability write up, or adding hosts to a vulnerability from the hitchhikers guide.

rollup : This script is slightly different from the others, in that it takes a --nessus [filename] paramter as well as --include= and --exclude= comma separated parameters. This script will parse a nessus file, and based on the parameters you set and will produce a .html file containing the following:

The names of all matching vulnerabilities (so you know what it actually matched)
A list of unique, sorted, html linked CVEs
A list of unique, sorted, html linked BIDs
A list of unique, sorted, html linked(where appropriate) other cross reference sources.
A 4 column tab separated table of unique, sorted IPs and ports.

You should be able to paste these straight into pages.

This script is useful for rolling up multiple similar vulnerabilities into 1 finding, for example:

--include="SSL Certificate","SSL Self" --exclude=2048 

will merge all of the SSL certificate errors into a single finding, but exclude the key length less than 2048 vulnerability. Ideally used for things like HP system management homepage, PHP and Apache vulns.

TODO:

Generally tidy up the scripts, add some error checking and see if I can find a way of making the rtf files a little larger. I'm assuming the hackish way I constructed them might be making it hard for the system parser to read.
