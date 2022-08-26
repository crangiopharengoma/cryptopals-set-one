# cryptopals

My attempt to complete the cryptopals challenges.

This project has two objectives:

1. Learn more about cryptosecurity
2. Improve my Rust skills

Sometimes this is probably going to reinvent wheels because I'm building my Rust knowledge at the same time as I'm
solving the crypto problems.

Some additional notes:

1. At the moment this has a dependency on openssl so you'll need to have this installed for this to work
2. Challenge 19 is solved with a standalone application. You can run this with cargo run --bin ctr-cracker
2. Challenge 31 and 32 rely on a server running on localhost 127.0.0.1. This can be started with the command cargo run
   --bin simple-server