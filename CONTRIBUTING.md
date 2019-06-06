# Contributing to this project

:+1::tada: First off, thanks for taking the time to contribute! :tada::+1:

## Pull requests

Please use a meaningful title in your pull requests name and commit messages (and they must start with capital letters).

Try to fit to the current code style, I will set a linter soon so it will be easier.

## Things you should know before you start

### About the "dev" branch

There is a development branch called "dev", it is not intended to be the one you commit onto.
It got an extra folder (named "dev") that contains some tools to build the module faster than the "master" build way (but is ~200MB heavyer).

Into the "dev" directory, use the `build` script to make two images : `jwt-nginx-devel-s0` and `jwt-nginx-devel-s1`.

To test `jwt-nginx-devel-s1` you can do:
```bash
./test jwt-nginx-devel-s1
```
or
```bash
# First terminal
docker run -p 8000:8000 --rm --name=jwt-nginx-test-devel jwt-nginx-devel-s1

# Second terminal
./test --current jwt-nginx-test-devel
```

Once you are statisfied with your changes, you can report them from the "dev" branch to your "feature" branch either by moving them manually or with a git [stach](https://git-scm.com/docs/git-stash) or [cherry-pick](https://git-scm.com/docs/git-cherry-pick).
