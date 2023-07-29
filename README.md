# Quickscope

Quickscope is a lightweight exploit thrower for attack-defense CTFs.
This entails being able to communicate with a game interface (the *tracker*) and being able to launch exploits (the *shooter*).

`pip install quickscope`

## How do I write an exploit?

Write an ordinary script that takes its input as the environment variables `$HOST` and `$FLAG_ID`.
You should hardcode the port used for the service, unless it is a very special variable service, in which case you should use `$PORT`.
`chmod +x` the script and make sure it has a shebang.
You should put the text `x-service-name: servicename` in your script somewhere so that the shooter knows to shoot it against the service `servicename`.

## How do I launch an exploit?

`quickscope --everyone --script my_exploit.py`

Your exploit must contain the text `x-service-name: <myservice>`, where `<myservice>` is replaced with the name of the service to fire at.

## How do I launch all my exploits forever?

`quickscope --forever --corpus my_exploits`

The difference between --everyone and --forever is that --everyone only shoots at each target for the current tick once.

## How do I set up the tracker?

In order for quickscope (the shooter) to fire exploits, it needs to be able to connect to the tracker.
The tracker is a python file that you should write for each CTF. Here's an example of it:

```python
from quickscope.tracker import Tracker

class MyTracker(Tracker):
    ...

if __name__ == '__main__':
    MyTracker.main()
```

You should implement the values marked as not implemented in tracker.py - this means `FLAG_REGEX`, `get_status`, `submit_flags`, and `instrument_targets`.
See [fake/stub_tracker.py](fake/stub_tracker.py) for an example implementation!

You can then directly run your script and it will start tracking the game.

If you're running the tracker in a non-hardcoded location, you will need to specify the `--server` argument to the shooter.
