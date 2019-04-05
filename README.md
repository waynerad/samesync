# sameSync
SameSync synchronizes files between machines and makes them the same.

* All communication encrypted with AES256.
* SHA256 used for keyed hash message authentication codes.
* End-to-end encryption allows the system to be used with untrusted servers.
* Complete, self-contained RPC system in 1,049 lines of code.
* Thorough unit testing of RPC system (more unit test code than production code).
* SHA256 used to detect changes to files.
* Dates & times used to determine newest versions of files -- takes into account differences in machine time settings from drift or time zones.
* Admin mode to set up system and diagnose and correct problems.
* Written in Golang.
* Works on all OSs where Go runs (Linux, Mac, Windows) -- handles OS-specific issues like backslashes vs slashes in directory paths correctly.
* Does not use HTTP for communication. Communicates directly using TCP sockets using Go's net package. Can run on any port you like. Can run on servers that don't have web servers (Apache, nginx, etc) installed.
* Uses sqlite3 (via Go's SQL interface in the sql package) for all data (on both client and server sides). Does not require the installation of a database server (MySQL, postgres, etc).
* Only dependency other than the Go standard library is sqlite3.
* Server does not use Go panics and handles errors gracefully without crashing.
* I've been using it to sync my own files since February 23, 2019.

# Issues

* This program's greatest security weakness is that keys are stored in plain text on the client and server machines. This enables the program to work with extreme convenience -- just type "same" and everything is made the same, no "password" prompts or anything. For what it's worth, other "secure" programs like ssh and scp have the same problem (the key is stored in plaintext in the .pem file).
* Related to that, there is no public key infrastructure, so symmetric keys need to be securely transported across the network as part of the setup process. I've been doing this by using scp or just cutting and pasting between ssh windows, relying on ssh to securely transport the keys across the network. If the keys are sent in an insecure way, for example by unencrypted email, then they could be intercepted as they cross the internet, and an attacker could gain access to all the files, including write access to the sync point.
* An attacker who can both obtain the files on the server and see all the network traffic in and out can impersonate users on functions that don't require the end-to-end encryption key (which the server is never allowed to see). This is because samesync does not have a public key infrastructure, which is what would be necessary to protect against such an attack. Although such an attacker can not obtain copies of the files, they can cause a certain amount of mischief (for example, they can delete files). Hopefully the inability to obtain the contents of files (or even the names of files) would sufficiently take away the incentive for anyone to do this in the real world, but we should think about ways the security could be improved to prevent the mischief.
* Possible time code issue if two different users are using the system and one of them undergoes a Daylight Saving Time shift while the other doesn't. (Different countries switch on and off Daylight Saving Time on different dates, for example the US and UK are about 2 weeks off.). While I'm confident the system works flawlessly in normal cases, because the clients query the server for the what time the server thinks it is and take into account differences in the clocks between different client computers and the server, edge cases where the clocks themselves change have never been tested. Hopefully the fact that the clocks change in the middle of the night will prevent this from being an issue for most users.
* If it matters to you that two users updating, editing, saving, and syncing the same file within seconds of each other causes edits from one user or the other to get lost, samesync is probably not the right tool for the job. You need a full-fledged version control system like git that can merge changes from multiple people. This program is ideally suited for users to share files with themselves -- i.e. to get copies of all their files on all their machines and keep them in sync.


