# NaCerl

An implementation of NaCl for Erlang that can be compiled on Windows and
Linux.

NaCl is an easy-to-use high-speed software library for network communication,
encryption, decryption, signatures etc. For more information see
[nacl.cr.yp.to](http://nacl.cr.yp.to/).

This project takes parts from various sources to ensure that the software can
be compiled on a Windows system. It should also compile on a Linux system, but
if you are using a Linux system you should probably opt for an Erlang
  implementation that uses libsodium, such as
  [enacl](https://github.com/jlouis/enacl).

This project is based on parts from various sources:

- Most of the C code comes from [TweetNaCL](https://tweetnacl.cr.yp.to/) .
  This is the actual implementation of the cryptographic functions.

- Some additional C code to generate random bytes comes from https://github.com/ultramancool/tweetnacl-usable.

- The Erlang code to create a NIF that uses the C implementation comes from 
https://github.com/tonyg/erlang-nacl. Nacerl is essentially a version of Tony
Garnock-Jones' project, but using TweetNaCl in stead of libsodium to
facilitate the compilation.

# Example

```erlang
1> rr("nacl.hrl").
[nacl_box_keypair,nacl_envelope]

2> #nacl_box_keypair{pk = PublicKey, sk = SecretKey} = nacl:box_keypair().
#nacl_box_keypair{pk = <<91,231,73,96,227,2,29,109,216,
                         185,247,252,203,223,128,51,194,
                         170,57,210,188,136,145,143,241,
                         19,6,...>>,
                  sk = <<30,193,12,53,65,254,33,83,210,116,42,182,7,97,73,
                         35,123,241,11,251,199,50,127,186,25,202,...>>}

3> Message = <<"this is a secret">>.
<<"this is a secret">>

4> Nonce = crypto:strong_rand_bytes(24). %% Nonce must be 24 bytes
<<201,16,213,16,7,166,221,39,0,47,251,186,164,141,57,92,
  152,218,43,176,243,223,126,16>>

5> #nacl_envelope{ciphertext = Encrypted} = nacl:box(Message, Nonce, PublicKey, SecretKey).
#nacl_envelope{nonce = <<201,16,213,16,7,166,221,39,0,47,
                         251,186,164,141,57,92,152,218,43,
                         176,243,223,126,16>>,
               ciphertext = <<164,122,249,242,77,152,181,74,124,83,197,
                              190,118,29,0,186,162,163,133,185,217,197,
                              150,66,96,134,...>>}

6> {ok, Message} = nacl:box_open(Encrypted, Nonce, PublicKey, SecretKey).
{ok,<<"this is a secret">>}
```
