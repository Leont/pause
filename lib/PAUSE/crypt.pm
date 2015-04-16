use strict;
use warnings;
package PAUSE::Crypt;

use Crypt::Eksblowfish::Bcrypt qw( bcrypt en_base64 );

sub hash_password {
  my ($pw) = @_;

  my $hash = bcrypt($pw, '$2$10$' . en_base64( _randchar(16) ));
}

my(@saltset) = (qw(. /), 0..9, "A".."Z", "a".."z");

sub _randchar ($) {
  local($^W) = 0; #we get a bogus warning here
  my($count) = @_;
  my $str = "";
  $str .= $saltset[int(rand(64))] while $count--;
  $str;
}

sub password_verify {
  my ($sent_pw, $crypt_pw) = @_;

  if (length $crypt_pw > 13) {
    my ($crypt_got) = crypt($sent_pw, $crypt_pw);
    return $crypt_got eq $crypt_pw;
  }

  my ($crypt_got) = bcrypt($sent_pw, $crypt_pw);
  return $crypt_got eq $crypt_pw;
}

1;
