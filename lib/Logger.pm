package Logger;
use strict;
use warnings;
use File::stat;
use Carp 'croak';
use Fcntl ':flock';
use constant DEFAULT_CALLED_DEPTH => 5; #user's func -> fatal -> log -> _message -> append -> print
use constant MAX_ROTATE_SIZE => 5_000_000; #5M bytes

$SIG{__DIE__} = \&handle_die;
our $Called_Depth = DEFAULT_CALLED_DEPTH; #if user wrapped 'fatal', then it should be bigger
my $Crash_log_file = 'crash_dump.log'; #default file for 'die_log'

my $singleton;

sub new {
    return $singleton if $singleton;
    my $class = shift;
    $singleton = bless {
        history => [],
        level => 'debug', #default level to log
        max_history_size => 10,
        path => undef,
        die_log => $Crash_log_file,
        rotate => 0,
        rotate_daily    => 0,
        append => 1,
        @_,
    }, ref( $class ) || $class;
    unlink $singleton->{path} if !$singleton->{append} && (-e $singleton->{path});
    if ($singleton->{path}) {
        if ($singleton->{path} =~ /(.*)(\.\w+)$/) {
            $singleton->{path_file} = $1;
            $singleton->{path_ext} = $2;
        }
        else {
            $singleton->{path_file} = $singleton->{path};
            $singleton->{path_ext} = '';
        }
    }
    $singleton;
    
}

# Supported log level
my $LEVEL = {trace => 0, debug => 1, info => 2, warn => 3, error => 4, fatal => 5};

sub is_init {
    return $singleton ? 1 : 0;
}

sub handle {
    my $self = shift;
    if (my $path = $self->{path}) {
        if ($self->{rotate}) {
            my $need_rotate = 1;
            if ( $self->{cur_path} && -e $self->{cur_path} ) {
                my $size = stat($self->{cur_path})->size;
                #print "\$size=$size\n";
                if (!$self->{rotate_daily} && $size < MAX_ROTATE_SIZE) {
                    $need_rotate = 0;
                }
            }
            if ($need_rotate) {
                my @time = localtime(time);
                if ($self->{rotate_daily}) {
                    $path = "$self->{path_file}_" . ($time[5]+1900) . "_" . ($time[4]+1) . "_" . "$time[3]$singleton->{path_ext}";
                } else {
                    $path = "$self->{path_file}_" . ($time[5]+1900) . "_" . ($time[4]+1) . "_" . "$time[3]_$time[2]_$time[1]_$time[0]$singleton->{path_ext}";
                }
                $self->{cur_path} = $path;
                #print "need rotate to new file: $path\n";
            }
            else {
                $path = $self->{cur_path};
            }
        }
        croak qq{Can't open log file "$path": $!}
            unless open my $file, '>>', $path;
        return $file;
    }
    return \*STDERR;
}

sub append {
    my ($self, $msg) = @_;
    return unless my $handle = $self->handle;
    
    flock $handle, LOCK_EX;
    $handle->print($msg) or croak "Can't write to log: $!";
    flock $handle, LOCK_UN;
}

sub trace { shift->log(trace => @_) }
sub debug { shift->log(debug => @_) }
sub info  { shift->log(info  => @_) }
sub warn { shift->log(warn => @_) }
sub error { shift->log(error => @_) }
sub fatal { shift->log(fatal => @_) }

sub log { shift->_message(lc shift, @_) }

sub is_level {
    $LEVEL->{lc pop} >= $LEVEL->{shift->{level}};
}


sub _format {
    my @time = localtime(shift);
    my @caller_info = caller($Called_Depth); #The caller func, support this package will be wrapped again, so use '5', or it should use '4'
    my @called_info = caller($Called_Depth - 1); #The called ('debug/warn/...') line number
    "[" . ($time[4]+1) . "-$time[3] $time[2]:$time[1]:$time[0]] [" . shift() . "] [$called_info[2]] [$caller_info[3]] " . join("\n", @_, '');
}

sub _message {
    my ($self, $level) = (shift, shift);
    return unless $self->is_level($level); #should be greater than default level
    my $msg = _format(time, $level, @_);
    if ($self->{max_history_size} > 0) {
        my $history = $self->{history};
        push @$history, $msg;
        shift @$history while @$history > $self->{max_history_size};
    }
    $self->append($msg);
}

sub handle_die {
    return if $^S; #if in an eval {}, don't want actually die
    my $mess = join('', @_);
    my @died_call = caller(0);
    $mess =~ s/\n$//;
    $mess = "Oops, died!\n -> $died_call[1], die at line $died_call[2], msg: '$mess'\n";
    
    my $i = 1;
    local $" = ", ";
    {
        package DB;
        while (my @parts = caller($i++)) {
            my $param = '';
            if( @DB::args ) {
                my @p = map { ref($_) eq 'ARRAY' ? '[' . join(', ', @$_) . ']' :
                              ref($_) eq 'HASH' ? '{' . join(', ', %$_) . '}' :
                              defined($_) ? $_ : 'undef' } @DB::args;
                $param = "@p";
            }
            $mess .= " -> $parts[1] $parts[2], $parts[3]($param)\n";
        }
    }
    eval {
        if( $singleton && $singleton->is_init ) {
            #local $Called_Depth;
            $Called_Depth += 2; #eval block and handle_die, they add 2 levels
            $singleton->fatal($mess) if $singleton->{path}; #crash log save to file if possible, or 'die' would print it directly
            $Called_Depth -= 2;
        }
        else {
            die "Crash without Logger instance!\n";
        }
    };
    if( $@ ) {
        chomp($@);
        my $crash_log = $singleton ? $singleton->{die_log} : $Crash_log_file;
        $mess = "%WARNING: $@ So log into '$crash_log'\n$mess";
        open( my $hf, ">", $crash_log ) or
            die "$mess\n\t####Can't create '$crash_log'!####";
        print $hf scalar localtime() . "\n";
        print $hf $mess . "\n";
        close $hf;
    }
    die $mess;
}

1;