#!/usr/bin/perl

use strict;
use warnings;
use Mail::GnuPG;
use MIME::Parser;
use Net::SMTP;
## Parse args
my $encrypt_mode   = 'pgpmime';
my $inline_flatten = 0;
my $skip_smime     = 0;
my $skip_ms_bug  = 0;
my @recipients     = ();
my @target = ();
{
	help() unless @ARGV;
	my @args = @ARGV;
	while( @args ){
		my $key = shift @args;
		if( $key =~ /^.+\@.+$/ ){
			push @recipients, $key;
		}
	}
}

$ENV{HOME} = (getpwuid($>))[7];
my $gpg = new Mail::GnuPG( always_trust => 1 );

@target=($recipients[0]);

## Make sure we have the appropriate public key for all recipients
     unless( $gpg->has_public_key( $target[0] ) ){
      print "No GPG key for ".$target[0]." - Passing decrypted";
     local $/ = undef;
     my $plain = <STDIN>;
	passToSendmail($plain);
  exit 0;
}

## Read the plain text email
  my $plain;
  {
     local $/ = undef;
     $plain = <STDIN>;
  }

## Parse the email
  my $mime;
  {
     my $parser = new MIME::Parser();
     $parser->decode_bodies(1);
     $parser->output_to_core(1);
     $mime = $parser->parse_data( $plain );
  }

## Test if it is already encrypted
  if( $gpg->is_encrypted( $mime ) ){
     passToSendmail($plain); exit 0;
  }

## Test if the email is S/MIME encrypted - already encrypted if so
  if( $skip_smime ) {
    if( $mime->mime_type =~ /^application\/pkcs7-mime/ ){
      passToSendmail($plain); exit 0;
    }
  } 

## Encrypt
  {
     my $code;
     if( $encrypt_mode eq 'pgpmime' ){
        $code = $gpg->mime_encrypt( $mime, @target );
     }  else {
	   passToSendmail($plain); exit 0;
     }

     if( $code ){
        passToSendmail($plain);
	exit 0;
     }
  }

## Remove some headers which might have been broken by the process of encryption
  $mime->head()->delete($_) foreach qw( DKIM-Signature DomainKey-Signature );

## Print out the encrypted version
  passToSendmail($mime->stringify);


sub passToSendmail {
	my $content = shift;
	my $smtp = Net::SMTP->new("127.0.0.1:10026");
	doLog("R0:".$recipients[0]." R1: ".$recipients[1]." R2:".$recipients[2]);
	$smtp->mail($recipients[1]);
	$smtp->to($recipients[0]);
	$smtp->data();
	$smtp->datasend($content);
	$smtp->dataend();
	$smtp->quit;
}

sub doLog {
	my $content = shift;
	my $filename = '/tmp/log';
	open(my $fh, '>>', $filename);
	print $fh $content."\n";
	close $fh;
}

sub help {
   print << "END_HELP";
This must be run from postfix.

END_HELP
  exit 0;
}
