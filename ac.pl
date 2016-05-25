use FindBin qw($Bin);
use lib "$Bin/lib";

use strict;
use warnings;
use Logger;
use Data::Dumper;
use File::Spec;
use File::Path qw(mkpath);
use IO::Socket;
use IO::Select;

$Logger::Called_Depth -= 1;
mkpath(File::Spec->catfile($Bin, 'log'));
my $log = Logger->new(path => File::Spec->catfile($Bin, 'log', 'ac.log'), rotate => 1, rotate_daily => 1);
#my $log = Logger->new();

use constant CONFIG_FILE        => "$Bin/ac.ini";
use constant SOCKET_MAX_RETRY   => 3;
use constant SOCKET_TIMEOUT     => 2;
use constant SOCKET_BUFFER_SIZE => 1024;
use constant USB_BOX_TCP_PORT   => 12352;
use constant APP_AGENT_TCP_PORT => 18888;
use constant CRLF             => chr(10) . chr(13);

main(@ARGV);

sub main {
    my $config = read_config(CONFIG_FILE);
    subs_var($config, @_);
    my ($ip, @cmds) = @_;
    unless ($ip && @cmds) {
        die "Need command line arguments: IP&&Commands!";
    }
    else {
        $log->debug("Run " . __FILE__ . " $ip @cmds!");
    }
    my ($port, $cmd) = translate_cmd(@cmds);
    my $sock = make_connect($ip, $port);
    if ( $sock ) {
        my $sel = IO::Select->new($sock);
        if( write_socket($sock, $sel, $cmd) ) {
            my $result = read_socket($sock, $sel);
            if (defined $result) {
                $log->debug("Got result: '$result'!");
                print "Result: $result!";
            }
            else {
                print STDERR "No response!";
            }
        }
        else {
            print STDERR "Send failure!";
        }
        close $sock;
    }
    else {
        print STDERR "No connection!";
    }
}

sub subs_var {
    my $config = shift;
    return unless @_;
    unless (ref $config->{global_var}) {
        $log->warn("No global var found in config!");
        return;
    }
    foreach (0..$#_) {
        $_[$_] =~ s/\$(\w+)/$config->{global_var}->{$1} or "\$$1"/eg;
    }
}

sub read_config {
    my $conf_file = shift;
    open(my $fh, $conf_file)
        or die "Failed to open config '$conf_file' to read, $!";
    my $global_var;
    my $config = {};
    while (<$fh>) {
        if (/^\s*\[Global_Var\]\s*/) {
            $global_var = 1;
            next;
        }
        if ($global_var) {
            if (/^\s*(\w+)\s*=(.*)/) {
                my ($k, $v) = ($1, $2);
                $v =~ s/^\s+|\s+$//g;
                $config->{global_var}->{$k} = $v;
                next;
            }
        }
    }
    $log->debug("read config:" . Dumper($config));
    return $config;
}

sub translate_cmd {
    if ($_[0] =~ /^usb$/i) {
        my ($port, $switch) = @_[1, 2];
        $log->debug("Translate USB command!");
        my $usb_cmd;
        #@_[0, 1, 2] = usb 1 on/off
        if ($switch =~ /^on$/i) {
            $usb_cmd = "USBBOX:USB:ON:$port";
        }
        elsif ($switch =~ /^off$/i) {
            $usb_cmd = "USBBOX:USB:OFF:$port";
        }
        #@_[0, 1, 2, 3] = usb delay 200 300
        elsif ($_[1] =~ /^delay$/i) {
            my ($power_delay, $data_delay) = @_[2, 3];
            if ($power_delay =~ /^\d+$/ && $data_delay =~ /^\d+$/) {
                $usb_cmd = "USBBOX:SYSTEM:SET_DELAY:$power_delay,$data_delay";
            }
            else {
                die "Unknown USBBOX command: '@_', should be format like 'usb delay 200 300'!";
            }
        }
        else {
            die "Unknown USBBOX command: '@_', should be format like 'usb 1 on/off'!";
        }
        return (USB_BOX_TCP_PORT, $usb_cmd);
    } else {
        my $cmd = '"' . join('" "', @_) . '"';
        $log->debug("Translate unknown command, forward '$cmd' to app agent!");
        return (APP_AGENT_TCP_PORT, $cmd);
    }
}

sub make_connect {
    my ($ip, $port) = @_;
    my $sock = IO::Socket::INET->new(
        PeerAddr => $ip,
        PeerPort => $port,
        Type     => SOCK_STREAM,
        Blocking => 1,
        Timeout  => SOCKET_TIMEOUT,
        Proto    => "tcp"
    );
    if ($sock) {
        return $sock;
    } else { 
        $log->error("Cann't connect to $ip:$port!");
    }
    return;
}

sub read_socket {
    my ($sock, $sel) = @_;
    foreach(1..SOCKET_MAX_RETRY) {
        my $fh_read = $sel->can_read(SOCKET_TIMEOUT);
        if ($fh_read) {
            my $rsp;
            my $bytes = $sock->read($rsp, SOCKET_BUFFER_SIZE, 0);
            if ($bytes) {
                $rsp =~ s/^\s+|\s+$//g;
                $log->debug("Receive: '$rsp'($bytes bytes)!");
                return $rsp;
            } elsif(defined $bytes) {
                $log->debug("Receive: EOF, quit!");
                return "";
            } else {
                $log->error("Receive error: $!");
                return;
            }
        } else {
            $log->warn("Recv timeout");
        }
    }
    return;
}

sub write_socket {
    my ($sock, $sel, $cmd) = @_;
    foreach(1..SOCKET_MAX_RETRY) {
        my $fh_write = $sel->can_write(SOCKET_TIMEOUT);
        if ($fh_write) {
            my $bytes = $sock->send($cmd . CRLF, 0);
            if ($bytes) {
                $log->debug("Succeed to send '$cmd'($bytes bytes)!");
                return 1;
            } else {
                $log->warn("send failed: $!, $@");
            }
            $sock->autoflush(1);
            last;
        } else {
            $log->warn("Send timeout!");
        }
    }
    return;
}