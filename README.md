# samesync
SameSync synchronizes files between machines and makes them the same.

* All communication encrypted with AES256.
* SHA256 used for keyed hash message authentication codes.
* Complete, self-contained RPC system in 927 lines of code.
* Thorough unit testing of RPC system (more unit test code than production code).
* SHA256 used to detect changes to files.
* Dates & times used to determine newest versions of files -- takes into account differences in machine time settings from drift or time zones.
* Admin mode to set up system and diagnose and correct problems.
* Written in Golang.
* Works on all OSs where Go runs (Linux, Mac, Window) -- handles OS-specific issues like backslashes vs slashes in directory paths correctly.
* Does not use HTTP for communication (communicates directly using TCP sockets using Go's net package)
* Server does not use Go panics and handles errors gracefully without crashing.
* Uses sqlite3 (via Go's SQL interface in the sql package) for all data (on both client and server sides). Does not require the installation of a database server.

