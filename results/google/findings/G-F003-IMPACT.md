An app the user installs, holding no real Android permission of any kind, obtains the
Google account signed into Google Home. No prompt, no interaction while it runs, nothing
visible on screen. It needs Google Home to have been opened since its process was last
killed, which I measured and which holds for anyone who uses the app. That is the concrete
gain, and it is the part I demonstrated end to end.

It also reaches `LockProximityReceiver`, which means it can make a first-party app run
its unlock-notification path on data the caller supplies. I did not get a notification out
of that path: the test account has no smart lock, and the device id carried in the
broadcast is resolved server side. So I am not claiming that as impact. It is why I think
the guard matters beyond the account disclosure.

Nothing in the app's permission list would look unusual to anyone reviewing it, since the
declared names are not real permissions and so appear nowhere in the permission UI. An app
doing this needs no `uses-permission` entry that a user or a reviewer would notice.
