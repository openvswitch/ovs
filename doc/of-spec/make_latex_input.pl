#!/usr/bin/perl -w

use strict;

sub handle_comment {
 my ($comment) = @_;
 
 my $next_line;
 do {
  $next_line = <INFILE>;
  chomp $next_line;
  $comment .=  $next_line."\n";
 } until ($next_line =~ m/\*\//);

 return $comment;
}

sub handle_define {
 my ($var, $val) = @_;
 open(OUTFILE, ">define/$var");
 print OUTFILE $val; 
 close(OUTFILE);
}

sub handle_multiline {
 my ( $dir, $filename, $line_orig, $last_comment) = @_;
   
 open(OUTFILE, ">$dir/$filename");
 #print OUTFILE "\\scriptsize\n";
 print OUTFILE "\\begin{footnotesize}\n";
 print OUTFILE "\\begin{verbatim}\n";
 #print OUTFILE "\\begin{lstlisting}[frame=htb]{$filename}\n";
 print OUTFILE $last_comment;
 print OUTFILE $line_orig;
 my $next_line;
 do {

  $next_line = <INFILE>;
  chomp $next_line; 

  print OUTFILE $next_line."\n";

 } until ($next_line eq '};');

 # add assertion line for structs
 if ($dir eq 'struct') {
  $next_line = <INFILE>;
  print OUTFILE $next_line;
 }
 print OUTFILE "\\end{verbatim}\n";
 #print OUTFILE "\\end{lstlisting}\n";
 print OUTFILE "\\end{footnotesize}\n";
 close(OUTFILE);
}

#----------------------------------------
use File::Path;

foreach my $type ('enum', 'struct', 'define') {
 if (-d $type) {
  rmtree ($type);
 }
 mkdir $type;
}

open(INFILE, "<../../include/openflow.h");

my $last_comment;
while(<INFILE>)
{
 # Good practice to store $_ value because
 # subsequent operations may change it.
 my($line) = $_;
 my $line_orig = $line;
 my @line_split = split ' ',$line;
 
 if (not defined($line_split[0])) {
  $last_comment = '';
 }
 # Handle single-line comment
 elsif ($line =~ m/^\/\*.*\*\//) {
  $last_comment = $line;
  #print $last_comment;
 }
 # Handle multi-line comment
 elsif ($line =~ m/^\/\*/) {
  $last_comment = handle_comment($line_orig);
  #print $last_comment; 
 }
 # Handle define
 elsif ($line_split[0] eq '#define') {
  handle_define($line_split[1],$line_split[2]);
  $last_comment = '';
 }
 # Handle enum
 elsif ($line_split[0] eq 'enum') {
  handle_multiline('enum', $line_split[1], $line_orig, $last_comment); 
  $last_comment = '';
 } 
 # Handle struct
 elsif ($line_split[0] eq 'struct') {
  handle_multiline('struct', $line_split[1], $line_orig, $last_comment); 
  $last_comment = '';
 } 

}
print "completed\n"; 
