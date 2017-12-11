# MyCipher
This Application was made with the intent of saving my passwords without any fear that some other people might get acess to.
I programmed everything in Java and used algorithms as AES-256, SHA-1 to provide confidenciality and SHA-256 to provide integrity to the files that save the password.
To run the application is pretty straightforward, just need to run the .sh script.
After running the script it will pop-up a terminal window and, if you run it for the first time, you'll need to put a password for the application
and confirming it, then it's asked the user to create two salt numbers that aren't needed to mesmerize.
You have finnaly installed the aplication, now it's only needed to fill all the passwords by adding (-a).
And the rest is pretty explicit, if you want to update some account details (-u), if you want to remove an account details (-r), if you
want to confirm the accounts details integrity (-c), if you want to exit the application (-q), and if you want to remove every password 
permanently and reseting the application to it's initial state (-uninstall).
