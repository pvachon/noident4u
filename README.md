#noident4u - The identd Stifler

Sometimes you really need identd to respond (i.e. for an ircd), but you really don't want
to respond with real information. noident4u is a simple daemon that you can specify a username
to automatically respond with. At that point, noident4u will then respond to every ident
request with that username. It's really that simple.

##Usage

```
./noident4u -d -u Administrator

  -d            - daemonize the process
  -u [username] - set the user to the specified value (in this case, Administrator)

```

Bing! And you're done.

