use strict;
use warnings;
package PAUSE::Crypt;

use Crypt::Passphrase;

my $passphrase = Crypt::Passphrase->new(
	encoder => {
		module  => 'Argon2',
		profile => 'moderate',
	},
	validators => [ 'Bcrypt::Compat', 'System' ],
);

sub hash_password {
  my ($pw) = @_;

  $pw = substr $pw, 0, 72;
  $passphrase->hash_password($pw);
}

sub password_verify {
  my ($sent_pw, $crypt_pw) = @_;
  return $passphrase->verify_password($sent_pw, $crypt_pw);
}

sub maybe_upgrade_stored_hash {
  my ($arg) = @_;

  return unless $passphrase->needs_rehash($arg->{old_hash});

  my $new_hash = hash_password($arg->{password});

  $arg->{dbh}->do(
    "UPDATE usertable SET password=? where user=?",
    +{},
    $new_hash,
    $arg->{username},
  );
}

1;
