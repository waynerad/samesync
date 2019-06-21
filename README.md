# samesync

samesync synchronizes files between machines and makes them the same. samesync is an "explicit" system -- unlike "implicit" systems like Dropbox, samesync only synchronizes files when you explicitly tell it to (on the command line), and it tells you explicity what files it is pushing off your machine or pulling on to it, so you know exactly what it is doing.

I like this system better than systems that "magically" synchronize things in the background. Maybe it is a "feeling of control" issue. I like the feeling of control that comes from having the system synchronize when I tell it. I like being able to see exactly what files are being synchronized as they are being synchronized. And I like being able to verify that, yes, right at this moment all my computers *are* synchronized.

I will acknowledge there is the downside that if you forget to synchronize, because synchronization does not happen "magically" automatically in the background, there is the possibility that your files could get out of sync. The program has a -z option that means "run continuously" that will mimic the behavior of Dropbox and other systems that synchronize automatically in the background. But because it works by sleeping for periods of time and then re-scanning the file system, rather than using OS-specific callbacks to get immediate notifications of changes to the filesystem, it is not real-time and can lag behind actual changes. In order to avoid relentlessly over-scanning the hard drive, the system tries to scale back the scanning when it perceives the system as being idle. I've stopped trying to find the optimal balance because I prefer to just run the program directly and explicitly as described above.

* All communication encrypted with AES256.
* SHA256 used for keyed hash message authentication codes.
* End-to-end encryption allows the system to be used with untrusted servers.
* Complete, self-contained RPC system in 1,049 lines of code.
* Thorough unit testing of RPC system (more unit test code than production code).
* SHA256 used to detect changes to files.
* Dates & times used to determine newest versions of files -- takes into account differences in machine time settings from drift or time zones.
* Admin mode to set up system and diagnose and correct problems.
* Written in Golang.
* Works on all OSs where Go runs (Linux, Mac, Windows) -- handles OS-specific issues like backslashes vs slashes in directory paths correctly. However, on Windows, the sqlite3 package for Go will not compile without gcc (the default compiler for Unix-style systems which includes Linux and Mac, which uses BSD Unix under the hood), and getting gcc to work on Windows is hard.
* Does not use HTTP for communication. Communicates directly using TCP sockets using Go's net package. Can run on any port you like. Can run on servers that don't have web servers (Apache, nginx, etc) installed.
* Uses sqlite3 (via Go's SQL interface in the sql package) for all data (on both client and server sides). Does not require the installation of a database server (MySQL, postgres, etc).
* Only dependency other than the Go standard library is sqlite3.
* Server does not use Go panics and handles errors gracefully without crashing.
* I've been using it to sync my own files since February 23, 2019.

# Quick Setup

Preliminaries: If you need to install Go, follow the instructions at https://golang.org/ .

If you get an error message  that looks like "fatal error: stdlib.h: No such file or directory" (happens on some Linux systems) during the setup process, fix it with:

$ sudo apt-get install g++

If you get an error saying git is missing, install with (Linux):

$ sudo apt install git

If you're not using Linux, install git using the instructions for your OS. Go is designed to use git in conjuction with the "go get" command.

You will need sqlite3. This is the one external dependency beyond the standard Go libraries and the packages that come with this GitHub repository.

$ go get github.com/mattn/go-sqlite3

If you are using Windows, you are in for a huge headache at this point because this sqlite3 package will not install on Windows without gcc, which is the default C compiler for Unix-style systems (which includes all Linuxes and Mac, because Mac uses BSD Unix under the hood). Getting gcc to work on Windows is hard. Maybe someday we'll have a proper Windows installer that will install pre-compiled binaries on your system like most Windows programs, but we're not at that stage yet.

Ok, now let's get on with the setup process:

1. Get the code

2. Build wrpc. This is the package that handles the actual encrypted RPC calls. Create a directory called "wrpc" in your go/src directory. Copy the contents of the "wrpc" directory from this project in there (wrpc.go and wrpc_test.go). In go/src/wrpc:

$ go install

3. Build samecommon. This is the package that has common functions between the client and server. Create a directory called "samecommon" in your go/src directory. Copy samecommon.go into this directory. In go/src/samecommon:

$ go install

4. Now, with the required packages installed, you just need to build the commands that you will run from the command line. To do this, cd into the "same" directory. Once the binaries are built, you'll need to move them to your executable directory. For me it ~/bin. If your executable directory is ~/bin, the instructions would be:

$ go build same.go

$ go build samed.go

$ mv same ~/bin

$ mv samed ~/bin

5. You'll need to do this on every machine (client and server). You can skip building the server executable (samed) on clients and you can skip building the client executable (same) on servers.

6. To set up the server: Create a subdirectory for the server to run in, and create a subdirectory under that for actually storing the files. The server will create a file called sameserver.db that it will use to keep track of what it is doing. You will need a subdirectory for each synchronized directory you synchronize between clients. The "Quick Setup" process described here will use one directory that you created, so if you're just going to do the "Quick Setup", you only need to create one directory. You'll also need to decide what port number to run the server on. Once you are ready, just type:

$ samed -q

This will create a file called samesetup.txt that you take to the clients. When you are ready to run the server, just use

$ samed

This can be combined with nohup to make a server that stays up all the time.

7. On the client, place the samesetup.txt file one directory UP from the directory you want synchronized.

$ same -q

8. On the first client, end-to-end encryption keys will be generated and added to the file. Copy this new samesetup.txt file to all the other clients so they all use the same end-to-end encryption key. Be careful copying this file across the network: make sure you use scp or WinSCP or some other secure copy system, as this file contains encryption keys -- the best thing is to use sneakernet and move the file from machine to machine manually such as on a USB stick.

Once the clients are set up, you synchronize them just by typing "same".

$ same

At this point, the system should be set up and all you have to do is type "same". You should delete all samesetup.txt files.


# Setup for complex scenarios

If you need more complex scenarios, you will need to create an admin account. On the server:

$ samed -a

It will give you an admin password.

On the client, log in with:

$ same -a

and enter the admin password. Once in admin mode, the following commands will become available:

* show users -- shows what user accounts the server recognizes. Quick Setup creates a user called "everybody", but you can create user accounts that identify individuals.
* show syncpoints -- shows which directories are being synchronized. These are called syncpoints (the directory on the server acts as a synrchonization point for multiple clients synchronizing that directory). Quick Setup creates a single syncpoint with the directory you give it, but the server can handle multiple syncpoints.
* show grants -- shows what users have access to what syncpoints. Users can be given read-only access instead of read-write. Quick Setup gives user "everybody" read-write access to the one syncpoint it creates.
* add user -- adds a user account to the server. Passwords are created by the server. Users are not allowed to choose their own passwords. They are not generally typed anyway and are stored in the client configuration.
* add syncpoint -- adds a syncpoint to the server. The syncpoint has a long hexadecimal ID that you will use to identify it in other commands.
* add grant -- grants a user access to a sync point. Access can be read-only or read-write. You'll need the username (email) of the user account and the ID (long hexadecimal code) of the syncpoint.
* del user -- deletes a user from the server.
* del syncpoint -- deletes a syncpoint.
* del grant -- takes access to a syncpoint away from a user.
* reset password -- resets the password for a user on the server.

The admin mode also has a command "local show config" that shows the client's local configuration, if you need to consult it while executing admin mode commands on the server.


# Issues

* This program's greatest security weakness is that keys are stored in plain text on the client and server machines. This enables the program to work with extreme convenience -- just type "same" and everything is made the same, no "password" prompts or anything. For what it's worth, other "secure" programs like ssh and scp have the same problem (the key is stored in plaintext in the .pem file).
* Related to that, there is no public key infrastructure, so symmetric keys need to be securely transported across the network as part of the setup process. I've been doing this by using scp or just cutting and pasting between ssh windows, relying on ssh to securely transport the keys across the network. If the keys are sent in an insecure way, for example by unencrypted email, then they could be intercepted as they cross the internet, and an attacker could gain access to all the files, including write access to the sync point.
* An attacker who can both obtain the files on the server and see all the network traffic in and out can impersonate users on functions that don't require the end-to-end encryption key (which the server is never allowed to see). This is because samesync does not have a public key infrastructure, which is what would be necessary to protect against such an attack. Although such an attacker can not obtain copies of the files, they can cause a certain amount of mischief (for example, they can delete files). Hopefully the inability to obtain the contents of files (or even the names of files) would sufficiently take away the incentive for anyone to do this in the real world, but we should think about ways the security could be improved to prevent the mischief.
* File names are encrypted with a fixed initialization vector. This is necessary so the same file on the client doesn't have multiple names on the server because every time the name is encrypted, it comes out different. However, it means that the security of file names is weaker than the security of file contents.
* Possible time code issue if two different users are using the system and one of them undergoes a Daylight Saving Time shift while the other doesn't. (Different countries switch on and off Daylight Saving Time on different dates, for example the US and UK are about 2 weeks off.). While I'm confident the system works flawlessly in normal cases, because the clients query the server for the what time the server thinks it is and take into account differences in the clocks between different client computers and the server, edge cases where the clocks themselves change have never been tested. Hopefully the fact that the clocks change in the middle of the night will prevent this from being an issue for most users.
* If it matters to you that two users updating, editing, saving, and syncing the same file within seconds of each other causes edits from one user or the other to get lost, samesync is probably not the right tool for the job. You need a full-fledged version control system like git that can merge changes from multiple people. This program is ideally suited for users to share files with themselves -- i.e. to get copies of all their files on all their machines and keep them in sync.
* People have raised the question of how efficient this program is compared with rsync. Because of the encryption, this system is less efficient than rsync. rsync is able to identify areas where large files have changed and send only the changes. So for example if you have a video and you change part of it in a video editor, rsync can find the part that changed and send only the change across the network. samesync is unable to do this because it does not have access to unencripted versions of the file on both ends.
* Similar to that, if you rename a file, samesync will delete the old file and re-download the new one on the other end. I'm working on an "efficient renaming" algorithm, but it is complicated by the fact that multiple copies of identical files can exist on both ends, and this appears to be a normal part of how people use computers. Even if you think you never make multiple copies of the same file, you probably use programs that do. (For example, git can create many small identical files that are initialized versions of new data structures. I've noticed other programs like the rust build system create identical files but I don't know why. So far it seems like identical files created by programs tend to be small, but I don't know if this is always the case. samesync can always identify identical files from the hash codes. Use samesync -d to have it tell you what your "duplicate" files are.)
