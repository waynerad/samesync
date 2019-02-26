# SameSync
SameSync synchronizes files between machines and makes them the same.

* All communication encrypted with AES256.
* SHA256 used for keyed hash message authentication codes.
* Complete, self-contained RPC system in 1,025 lines of code.
* Thorough unit testing of RPC system (more unit test code than production code).
* SHA256 used to detect changes to files.
* Dates & times used to determine newest versions of files -- takes into account differences in machine time settings from drift or time zones.
* Admin mode to set up system and diagnose and correct problems.
* Written in Golang.
* Works on all OSs where Go runs (Linux, Mac, Window) -- handles OS-specific issues like backslashes vs slashes in directory paths correctly.
* Does not use HTTP for communication. Communicates directly using TCP sockets using Go's net package. Can run on any port you like. Can run on servers that don't have web servers installed (Apache, nginx, etc).
* Server does not use Go panics and handles errors gracefully without crashing.
* Uses sqlite3 (via Go's SQL interface in the sql package) for all data (on both client and server sides). Does not require the installation of a database server (MySQL, postgres, etc).
* I've been using it to sync my own files since February 23, 2019.

# Bugs/issues

* This program's greatest security weakness is that keys are stored in plain text on the client and server machines. This enables the program to work with extreme convenience -- just type "same" and everything is made the same, no "password" prompts or anything.
* Related to that, there is no public key infrastructure, so symmetric keys need to be securely transported across the network as part of the setup process. I've been doing this by using scp or just cutting and pasting between ssh windows, relying on ssh to securely transport the keys across the network. If the keys are sent in an insecure way, for example by unencrypted email, then they could be intercepted as they cross the internet, and an attacker could gain access to all the files, including write access to the sync point.
* Possible time code issue if two different users are using the system and one of them undergoes a Daylight Saving Time shift while the other doesn't. (Different countries switch on and off Daylight Saving Time on different dates, for example the US and UK are about 2 weeks off.). While I'm confident the system works flawlessly in normal cases, because the clients query the server for the what time the server thinks it is and take into account differences in the clocks between different client computers and the server, edge cases where the clocks themselves change have never been tested. Hopefully the fact that the clocks change in the middle of the night will prevent this from being an issue for most users.
* If it matters to you that two users updating, editing, saving, and syncing the same file within seconds of each other causes edits from one user or the other to get lost, samesync is probably not the right tool for the job. You need a full-fledged version control system like git that can merge changes from multiple people.


